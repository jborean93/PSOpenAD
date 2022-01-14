using PSOpenAD.LDAP;
using System;
using System.Buffers;
using System.Collections.Concurrent;
using System.IO;
using System.IO.Pipelines;
using System.Linq;
using System.Net.Security;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

namespace PSOpenAD
{
    internal class OpenADConnection : IDisposable
    {
        private readonly object _closeLock = new();
        private readonly Task _recvTask;
        private readonly Task _sendTask;
        private readonly ConcurrentDictionary<int, BlockingCollection<LDAPMessage>> _messages = new();
        private readonly ManualResetEventSlim _tlsReplaceEvent = new(true);
        private readonly TcpClient _connection;
        private readonly int _waitTimeout;
        private bool _closed;
        private Stream _ioStream;
        private CancellationTokenSource _recvCancel = new();
        private Exception? _taskFailure;

        public LDAPSession Session { get; set; }
        public SecurityContext? SecurityContext { get; set; }

        public bool Sign { get; set; }
        public bool Encrypt { get; set; }
        public bool IsClosed => _taskFailure != null || _closed;

        public OpenADConnection(TcpClient connection, Stream stream, LDAPSession session, int waitTimeout)
        {
            Session = session;

            _connection = connection;
            _ioStream = stream;
            _waitTimeout = waitTimeout;
            _recvTask = Task.Run(Recv);
            _sendTask = Task.Run(Send);
        }

        /// <summary>Wait for a response from the LDAP server.</summary>
        /// <param name="messageId">Wait for the response for the request that generated this id.</param>
        /// <param name="timeout">Override the default timeout to wait for a response.</param>
        /// <param name="cancelToken">Cancel token used to cancel the wait operation.</param>
        /// <returns>The LDAP message response.</returns>
        public LDAPMessage WaitForMessage(int messageId, int? timeout = null, CancellationToken cancelToken = default)
        {
            BlockingCollection<LDAPMessage> queue;
            lock (_messages)
            {
                // The lock ensures that either the _taskFailure is set on a cancelled operation or the LDAP queue has
                // an entry and set to null for the check later on.
                if (_taskFailure != null)
                    throw _taskFailure;

                queue = _messages.GetOrAdd(messageId,
                    new BlockingCollection<LDAPMessage>(new ConcurrentQueue<LDAPMessage>()));
            }

            if (!queue.TryTake(out var msg, timeout ?? _waitTimeout, cancelToken))
            {
                if (_taskFailure != null)
                {
                    throw _taskFailure;
                }
                else
                {
                    throw new TimeoutException($"Timeout while waiting response of {messageId}");
                }
            }

            return msg;
        }

        /// <summary>Remove the wait queue for this request message identifier.</summary>
        /// <remarks>This should be called once all the messages for this request has been received.</remarks>
        /// <param name="messageId">The request message id to remove from the queue.</param>
        public void RemoveMessageQueue(int messageId)
        {
            _messages.TryRemove(messageId, out var _);
        }

        /// <summary>Upgrades the socket stream to a TLS wrapped one.</summary>
        /// <remarks>
        /// This is used for a StartTLS or LDAPS connection to replace the socket stream with a TLS one.
        /// </remarks>
        /// <param name="authOptions">The TLS client authentication details used during the handshake.</param>
        /// <param name="cancelToken">Token to cancel the TLS handshake connection.</param>
        public SslStream SetTlsStream(SslClientAuthenticationOptions authOptions,
            CancellationToken cancelToken = default)
        {
            // Mark this event as unset and cancel the Recv task. This task will wait until the event is set again
            // before continuing with the replace IOStream which is the SSL context that was created.
            _tlsReplaceEvent.Reset();
            _recvCancel.Cancel();

            SslStream tls = new(_ioStream, false);
            tls.AuthenticateAsClientAsync(authOptions, cancelToken).GetAwaiter().GetResult();
            _ioStream = tls;

            _recvCancel = new CancellationTokenSource();
            _tlsReplaceEvent.Set();

            return tls;
        }

        private async Task Send()
        {
            PipeReader reader = Session.Outgoing;

            try
            {
                while (await WrappedSend(reader)) { }
            }
            // Ignores socket closures as they are expected if the server closed their end.
            catch (IOException e) when (e.InnerException is SocketException) { }
            catch (Exception e)
            {
                // Unknown failure - propagate back to the task waiters.
                CancelTasks(e);
            }
        }

        private async Task<bool> WrappedSend(PipeReader reader)
        {
            ReadResult result = await reader.ReadAsync();
            ReadOnlySequence<byte> buffer = result.Buffer;

            if (SecurityContext != null && Sign)
            {
                byte[] wrappedData;
                if (buffer.IsSingleSegment)
                {
                    wrappedData = SecurityContext.Wrap(buffer.FirstSpan, Encrypt);
                }
                else
                {
                    ReadOnlyMemory<byte> toWrap = buffer.ToArray();
                    wrappedData = SecurityContext.Wrap(toWrap.Span, Encrypt);
                }

                byte[] lengthData = BitConverter.GetBytes(wrappedData.Length);
                if (BitConverter.IsLittleEndian)
                    Array.Reverse(lengthData);

                // FIXME: Check if the below can work to save allocating a new arrya and copying.
                // await _ioStream.WriteAsync(lengthData, 0, lengthData.Length);
                // await _ioStream.WriteAsync(wrappedData, 0, wrappedData.Length);
                ArrayPool<byte> shared = ArrayPool<byte>.Shared;
                byte[] rentedArray = shared.Rent(wrappedData.Length + 4);
                try
                {
                    Buffer.BlockCopy(lengthData, 0, rentedArray, 0, lengthData.Length);
                    Buffer.BlockCopy(wrappedData, 0, rentedArray, lengthData.Length, wrappedData.Length);
                    await _ioStream.WriteAsync(rentedArray, 0, lengthData.Length + wrappedData.Length);
                }
                finally
                {
                    shared.Return(rentedArray);
                }
            }
            else
            {
                // FIXME: See if there is a better way to do this.
                ReadOnlyMemory<byte> data = buffer.ToArray();
                await _ioStream.WriteAsync(data);
            }

            await _ioStream.FlushAsync();

            reader.AdvanceTo(buffer.End);

            return !result.IsCompleted;
        }

        private async Task Recv()
        {
            Pipe socket = new();
            Pipe unwrapper = new();

            Task socketReader = RecvSocket(socket.Writer);
            Task encryptionProcessor = RecvWrapped(socket.Reader, unwrapper.Writer);
            Task messageProcessor = RecvProcess(unwrapper.Reader);
            await Task.WhenAll(socketReader, encryptionProcessor, messageProcessor);
        }

        private async Task RecvSocket(PipeWriter writer)
        {
            while (true)
            {
                Memory<byte> memory = writer.GetMemory(_connection.ReceiveBufferSize);
                try
                {
                    int bytesRead = await _ioStream.ReadAsync(memory, _recvCancel.Token);
                    if (bytesRead == 0)
                        break;

                    writer.Advance(bytesRead);
                }
                catch (OperationCanceledException)
                {
                    if (!_tlsReplaceEvent.IsSet)
                    {
                        // SetTlsStream has cancelled the recv while it replaces the stream wtih an SslStream for
                        // StartTLS/LDAPS. Wait until the event has been fired before trying again with the new stream.
                        _tlsReplaceEvent.Wait();
                        continue;
                    }
                    else
                    {
                        // Cancelled in Dispose, end the task
                        break;
                    }
                }
                catch (IOException e) when (e.InnerException is SocketException)
                {
                    // Typically due to the server closing the socket before we had a chance to cancel it ourselves.
                    break;
                }
                catch (Exception e)
                {
                    // Unknown failure - propagate back to the task waiters.
                    CancelTasks(e);
                    break;
                }

                FlushResult result = await writer.FlushAsync();
                if (result.IsCompleted)
                    break;
            }

            await writer.CompleteAsync();
        }

        private async Task RecvWrapped(PipeReader reader, PipeWriter writer)
        {
            while (true)
            {
                ReadResult result = await reader.ReadAsync();
                ReadOnlySequence<byte> buffer = result.Buffer;

                long consumed;
                try
                {
                    if (buffer.Length == 0)
                    {
                        consumed = 0;
                    }
                    else if (SecurityContext != null && Sign)
                    {
                        consumed = await ProcessSealedMessage(SecurityContext, buffer, writer);
                    }
                    else
                    {
                        foreach (ReadOnlyMemory<byte> segment in buffer)
                        {
                            await writer.WriteAsync(segment);
                        }
                        consumed = buffer.Length;
                    }
                }
                catch (Exception e)
                {
                    // Unknown failure - propagate back to the task waiters.
                    CancelTasks(e);
                    break;
                }

                reader.AdvanceTo(buffer.Slice(0, consumed).End, buffer.End);
                if (result.IsCompleted)
                    break;
            }

            await reader.CompleteAsync();
            await writer.CompleteAsync();
        }

        private async Task RecvProcess(PipeReader reader)
        {
            while (true)
            {
                ReadResult result = await reader.ReadAsync();
                ReadOnlySequence<byte> buffer = result.Buffer;

                int consumed;
                try
                {
                    if (buffer.Length == 0)
                    {
                        consumed = 0;
                    }
                    else if (buffer.IsSingleSegment)
                    {
                        consumed = TryReadMessage(buffer.FirstSpan);
                    }
                    else
                    {
                        // FIXME: Is there a better way to do this.
                        ReadOnlyMemory<byte> data = buffer.ToArray();
                        consumed = TryReadMessage(data.Span);
                    }
                }
                catch (Exception e)
                {
                    // Unknown failure - propagate back to the task waiters.
                    CancelTasks(e);
                    break;
                }

                reader.AdvanceTo(buffer.Slice(0, consumed).End, buffer.End);
                if (result.IsCompleted)
                    break;
            }

            await reader.CompleteAsync();
        }

        private async Task<long> ProcessSealedMessage(SecurityContext context, ReadOnlySequence<byte> data, PipeWriter writer)
        {
            long consumed = 0;
            while (data.Length > 4)
            {
                int length = ReadWrappedLength(data);
                if (data.Length < 4 + length)
                    break;

                ReadOnlySequence<byte> dataSequence = data.Slice(4, length);
                byte[] unwrappedData;
                if (dataSequence.IsSingleSegment)
                {
                    unwrappedData = context.Unwrap(dataSequence.FirstSpan);
                }
                else
                {
                    ReadOnlyMemory<byte> wrappedData = dataSequence.ToArray();
                    unwrappedData = context.Unwrap(wrappedData.Span);
                }
                await writer.WriteAsync(unwrappedData);

                data = data.Slice(4 + length);
                consumed += 4 + length;
            }

            return consumed;
        }

        private int ReadWrappedLength(ReadOnlySequence<byte> data)
        {
            Span<byte> rawLength = stackalloc byte[4];
            data.Slice(0, 4).CopyTo(rawLength);
            if (BitConverter.IsLittleEndian)
                rawLength.Reverse();

            return BitConverter.ToInt32(rawLength);
        }

        private int TryReadMessage(ReadOnlySpan<byte> data)
        {
            int totalConsumed = 0;
            while (data.Length > 0)
            {
                LDAPMessage? message = Session.ReceiveData(data, out var consumed);
                if (message == null)
                    break;

                data = data[consumed..];
                totalConsumed += consumed;

                // The server may send this just before the connection is disconnected, this is a fatal error.
                const string terminationOid = "1.3.6.1.4.1.1466.20036";
                if (message is ExtendedResponse extResp && extResp.MessageId == 0 && extResp.Name == terminationOid)
                {
                    string errorMsg = "Server unexpectedly shut down connection";
                    if (!string.IsNullOrEmpty(extResp.Result.DiagnosticsMessage))
                        errorMsg += $" - {extResp.Result.DiagnosticsMessage}";

                    CancelTasks(new InvalidOperationException(errorMsg), forceException: true);
                    break;
                }

                BlockingCollection<LDAPMessage> queue = _messages.GetOrAdd(message.MessageId,
                    new BlockingCollection<LDAPMessage>(new ConcurrentQueue<LDAPMessage>()));
                queue.Add(message);
            }

            return totalConsumed;
        }

        private void CancelTasks(Exception failureDetails, bool forceException = false)
        {
            lock (_closeLock)
            {
                if (_taskFailure == null || forceException)
                    _taskFailure = failureDetails;

                // Lock to ensure any caller to WaitForMessage will have either already created the queue or checks
                // beforehand that the connection has failed.
                lock (_messages)
                {
                    foreach (BlockingCollection<LDAPMessage> msgQueue in _messages.Values)
                    {
                        if (!msgQueue.IsCompleted)
                        {
                            msgQueue.CompleteAdding();
                        }
                    }
                }
            }
        }

        public void Dispose()
        {
            // Cancel the recv so it doesn't fail with connection reset by peer
            if (!_recvCancel.IsCancellationRequested)
                _recvCancel.Cancel();
            _recvTask.GetAwaiter().GetResult();

            // The unbind response also marks the LDAP outgoing reader as done
            if (Session.State == SessionState.Opened)
                Session.Unbind();
            else
                Session.Close();
            _sendTask.GetAwaiter().GetResult();

            Session.Outgoing.Complete();

            // Once both tasks are complete dispose of the stream and connection.
            _ioStream.Dispose();
            _connection.Dispose();
            SecurityContext?.Dispose();

            _closed = true;

            GC.SuppressFinalize(this);
        }
        ~OpenADConnection() { Dispose(); }
    }
}

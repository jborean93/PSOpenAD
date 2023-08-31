using PSOpenAD.LDAP;
using System;
using System.Buffers;
using System.Collections.Concurrent;
using System.IO;
using System.IO.Pipelines;
using System.Linq;
using System.Net.Security;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace PSOpenAD.Module;

internal class OpenADConnection : IADConnection
{
    private readonly object _closeLock = new();
    private readonly Task _recvTask;
    private readonly Task _sendTask;
    private readonly ConcurrentDictionary<int, BlockingCollection<LDAPMessage>> _messages = new();
    private readonly ManualResetEventSlim _tlsReplaceEvent = new(true);
    private readonly TcpClient _connection;
    private readonly int _waitTimeout;
    private readonly StreamWriter? _traceWriter;
    private readonly PipeReader _pipeReader;
    private bool _closed;
    private Stream _ioStream;
    private CancellationTokenSource _recvCancel = new();
    private Exception? _taskFailure;
    private bool _signed;
    private bool _encrypted;
    private SecurityContext? _securityContext;

    public LDAPSession Session { get; set; }

    public bool IsClosed => _taskFailure != null || _closed;

    public OpenADConnection(TcpClient connection, Stream stream, int waitTimeout, string? tracePath)
    {
        if (!string.IsNullOrWhiteSpace(tracePath))
        {
            _traceWriter = new(File.Open(tracePath, FileMode.Create, FileAccess.Write,
                FileShare.ReadWrite | FileShare.Delete), new UTF8Encoding(false));
        }
        PipelineLDAPSession ldapSession = new(writer: _traceWriter);
        _pipeReader = ldapSession.Outgoing;
        Session = ldapSession;

        _connection = connection;
        _ioStream = stream;
        _waitTimeout = waitTimeout;
        _recvTask = Task.Run(Recv);
        _sendTask = Task.Run(Send);
    }

    public LDAPMessage WaitForMessage(int messageId, int? timeout = null, CancellationToken cancelToken = default)
    {
        BlockingCollection<LDAPMessage> queue;
        lock (_messages)
        {
            // The lock ensures that either the _taskFailure is set on a cancelled operation or the LDAP queue has
            // an entry and set to null for the check later on.
            if (_taskFailure != null)
                throw new LDAPException($"Message recv failure: {_taskFailure.Message}", _taskFailure);

            queue = _messages.GetOrAdd(messageId,
                new BlockingCollection<LDAPMessage>(new ConcurrentQueue<LDAPMessage>()));
        }

        if (!queue.TryTake(out var msg, timeout ?? _waitTimeout, cancelToken))
        {
            if (_taskFailure != null)
            {
                throw new LDAPException($"Message recv failure: {_taskFailure.Message}", _taskFailure);
            }
            else
            {
                throw new TimeoutException($"Timeout while waiting response of {messageId}");
            }
        }

        return msg;
    }

    public void RemoveMessageQueue(int messageId)
    {
        _messages.TryRemove(messageId, out var _);
    }

    public SslStream SetTlsStream(SslClientAuthenticationOptions authOptions,
        CancellationToken cancelToken = default)
    {
        // Mark this event as unset and cancel the Recv task. This task will wait until the event is set again
        // before continuing with the replace IOStream which is the SSL context that was created.
        _tlsReplaceEvent.Reset();
        _recvCancel.Cancel();
        try
        {
            SslStream tls = new(_ioStream, false);
            tls.AuthenticateAsClientAsync(authOptions, cancelToken).GetAwaiter().GetResult();
            _ioStream = tls;

            return tls;
        }
        finally
        {
            _recvCancel = new CancellationTokenSource();
            _tlsReplaceEvent.Set();
        }
    }

    public void AssociateSecurityContext(SecurityContext context, bool sign, bool encrypt)
    {
        _securityContext = context;
        _signed = sign;
        _encrypted = encrypt;
    }

    private async Task Send()
    {
        try
        {
            while (await WrappedSend(_pipeReader)) { }
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

        if (_securityContext != null && _signed)
        {
            byte[] wrappedData;
            if (buffer.IsSingleSegment)
            {
                wrappedData = _securityContext.Wrap(buffer.FirstSpan, _encrypted);
            }
            else
            {
                ReadOnlyMemory<byte> toWrap = buffer.ToArray();
                wrappedData = _securityContext.Wrap(toWrap.Span, _encrypted);
            }

            byte[] lengthData = BitConverter.GetBytes(wrappedData.Length);
            if (BitConverter.IsLittleEndian)
                Array.Reverse(lengthData);

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

        Session.Close();
        _closed = true;
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
                else if (_securityContext != null && _signed)
                {
                    consumed = await ProcessSealedMessage(_securityContext, buffer, writer);
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
        _pipeReader.Complete();

        // Once both tasks are complete dispose of the stream and connection.
        _ioStream.Dispose();
        _connection.Dispose();
        _securityContext?.Dispose();
        _traceWriter?.Dispose();

        _closed = true;

        GC.SuppressFinalize(this);
    }

    ~OpenADConnection() { Dispose(); }
}

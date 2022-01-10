using PSOpenAD.LDAP;
using System;
using System.Buffers;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.IO.Pipelines;
using System.Linq;
using System.Management.Automation;
using System.Net.Security;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace PSOpenAD
{
    public sealed class OpenADSessionOptions
    {
        public bool NoEncryption { get; set; }
        public bool NoSigning { get; set; }
        public bool NoChannelBinding { get; set; }
        public bool SkipCertificateCheck { get; set; }
    }

    public sealed class OpenADSession
    {
        public Uri Uri { get; }

        public AuthenticationMethod Authentication { get; }

        public bool IsSigned { get; }

        public bool IsEncrypted { get; }

        public string DefaultNamingContext { get; internal set; }

        public bool IsClosed { get; internal set; }

        internal OpenADConnection Connection { get; }

        internal LDAPSession Ldap => Connection.Session;

        internal AttributeTransformer AttributeTransformer { get; }

        internal OpenADSession(OpenADConnection connection, Uri uri, AuthenticationMethod auth,
            bool isSigned, bool isEncrypted, string defaultNamingContext, AttributeTransformer transformer)
        {
            Connection = connection;
            Uri = uri;
            Authentication = auth;
            IsSigned = isSigned;
            IsEncrypted = isEncrypted;
            DefaultNamingContext = defaultNamingContext;
            AttributeTransformer = transformer;
            IsClosed = false;
        }

        internal void Close()
        {
            if (!IsClosed)
                Connection.Dispose();
            IsClosed = true;
        }
    }

    internal sealed class OpenADSessionFactory
    {
        internal static OpenADSession CreateOrUseDefault(Uri uri, PSCredential? credential, AuthenticationMethod auth,
            bool startTls, OpenADSessionOptions sessionOptions, CancellationToken cancelToken = default,
            PSCmdlet? cmdlet = null)
        {
            if (GlobalState.ImplicitSessions.TryGetValue(uri.ToString(), out var session) && !session.IsClosed)
            {
                cmdlet?.WriteVerbose("Using cached OpenADSession");
                return session;
            }
            else
            {
                session = Create(uri, credential, auth, startTls, sessionOptions, cancelToken, cmdlet: cmdlet);
                GlobalState.AddSession(uri.ToString(), session);

                return session;
            }
        }

        internal static OpenADSession Create(Uri uri, PSCredential? credential, AuthenticationMethod auth,
            bool startTls, OpenADSessionOptions sessionOptions, CancellationToken cancelToken = default,
            PSCmdlet? cmdlet = null)
        {
            cmdlet?.WriteVerbose($"Connecting to {uri}");
            TcpClient client = new();
            Task connectTask = client.ConnectAsync(uri.DnsSafeHost, uri.Port);
            if (!connectTask.Wait(10000, cancelToken))
                throw new TimeoutException();
            connectTask.GetAwaiter().GetResult();

            OpenADConnection connection = new(client, client.GetStream(), new LDAPSession());
            try
            {
                bool transportIsTls = false;
                ChannelBindings? channelBindings = null;
                if (startTls || uri.Scheme.Equals("ldaps", StringComparison.InvariantCultureIgnoreCase))
                {
                    transportIsTls = true;
                    channelBindings = ProcessTlsOptions(connection, uri, startTls, sessionOptions, cancelToken, cmdlet);
                }

                Authenticate(connection, uri, auth, credential, channelBindings, transportIsTls, sessionOptions,
                    cancelToken, cmdlet);

                // Attempt to get the default naming context.
                Dictionary<string, string[]> rootInfo = LdapQuery(connection, "", SearchScope.Base,
                    new FilterPresent("objectClass"), new string[] { "defaultNamingContext", "subschemaSubentry" },
                    cancelToken);

                // While AD should have this some LDAP servers do not, just try with no base value.
                string defaultNamingContext = "";
                if (rootInfo.ContainsKey("defaultNamingContext"))
                    defaultNamingContext = (rootInfo["defaultNamingContext"] ?? new string[] { "" })[0];

                // Attempt to get the schema info of the host so the code can parse the raw LDAP attribute values into
                // the required PowerShell type.
                string subschemaSubentry = rootInfo["subschemaSubentry"][0];
                AttributeTransformer attrInfo = QueryAttributeTypes(connection, subschemaSubentry, cancelToken,
                    cmdlet);

                return new OpenADSession(connection, uri, auth, transportIsTls || connection.Sign,
                    transportIsTls || connection.Encrypt, defaultNamingContext, attrInfo);
            }
            catch
            {
                connection.Dispose();
                throw;
            }
        }

        /// <summary>Performs StartTLS on the LDAP connection and completes the TLS handshake.</summary>
        /// <param name="connection">The OpenAD connection.</param>
        /// <param name="uri">The URI used for the connection.</param>
        /// <param name="startTls">Whether to perform StartTLS on an LDAP connection.</param>
        /// <param name="sessionOptions">More session options to control the TLS behaviour.</param>
        /// <param name="cancelToken">Cancellation token for any network requests.</param>
        /// <param name="cmdlet">PSCmdlet to write verbose records to.</param>
        /// <returns>The channel binding data used with SASL authentication if available.</returns>
        private static ChannelBindings? ProcessTlsOptions(OpenADConnection connection, Uri uri, bool startTls,
            OpenADSessionOptions sessionOptions, CancellationToken cancelToken, PSCmdlet? cmdlet)
        {
            if (sessionOptions.NoEncryption || sessionOptions.NoSigning)
                throw new ArgumentException("Cannot disable encryption or signatures for TLS based connection");

            if (startTls && uri.Scheme.Equals("ldaps", StringComparison.InvariantCultureIgnoreCase))
            {
                throw new ArgumentException("Cannot use StartTLS over an LDAPS connection");
            }
            else if (startTls)
            {
                cmdlet?.WriteVerbose("Sending StartTLS request to the server");
                int startTlsId = connection.Session.ExtendedRequest("1.3.6.1.4.1.1466.20037");

                ExtendedResponse extResp = (ExtendedResponse)connection.WaitForMessage(startTlsId, cancelToken);
                connection.RemoveMessageQueue(startTlsId);
                if (extResp.Result.ResultCode != LDAPResultCode.Success)
                    throw new LDAPException(extResp.Result);
            }

            cmdlet?.WriteVerbose("Performing TLS handshake on connection");
            SslClientAuthenticationOptions authOptions = new()
            {
                // FIXME: only blinding accept if session options want this.
                RemoteCertificateValidationCallback = ValidateServerCertificate,
                TargetHost = uri.DnsSafeHost,
            };
            SslStream tls = connection.SetTlsStream(authOptions, cancelToken);

            ChannelBindings? cbt = null;
            if (!sessionOptions.NoChannelBinding)
                cbt = GetTlsChannelBindings(tls);

            return cbt;
        }

        /// <summary>Get channel binding data for SASL auth</summary>
        /// <remarks>
        /// While .NET has it's own function to retrieve this value it returns an opaque pointer with no publicly
        /// documented structure. To avoid using any internal implementation details this just does the same work to
        /// achieve the same result.
        /// </remarks>
        /// <param name="tls">The SslStream that has been authenticated.</param>
        /// <returns>The channel binding data if available.</returns>
        private static ChannelBindings? GetTlsChannelBindings(SslStream tls)
        {
            using X509Certificate2 cert = new(tls.RemoteCertificate);

            byte[] certHash;
            switch (cert.SignatureAlgorithm.Value)
            {
                case "2.16.840.1.101.3.4.2.2": // SHA384
                case "1.2.840.10045.4.3.3": // SHA384ECDSA
                case "1.2.840.113549.1.1.12": // SHA384RSA
                    using (SHA384 hasher = SHA384.Create())
                        certHash = hasher.ComputeHash(cert.RawData);
                    break;

                case "2.16.840.1.101.3.4.2.3": // SHA512
                case "1.2.840.10045.4.3.4": // SHA512ECDSA
                case "1.2.840.113549.1.1.13": // SHA512RSA
                    using (SHA512 hasher = SHA512.Create())
                        certHash = hasher.ComputeHash(cert.RawData);
                    break;

                // Older protocols default to SHA256, use this as a catch all in case of a weird algorithm.
                default:
                    using (SHA256 hasher = SHA256.Create())
                        certHash = hasher.ComputeHash(cert.RawData);
                    break;
            }

            byte[] prefix = Encoding.UTF8.GetBytes("tls-server-end-point:");
            byte[] finalCB = new byte[prefix.Length + certHash.Length];
            Array.Copy(prefix, 0, finalCB, 0, prefix.Length);
            Array.Copy(certHash, 0, finalCB, prefix.Length, certHash.Length);

            return new ChannelBindings()
            {
                ApplicationData = finalCB,
            };
        }

        /// <summary>Authenticates with the LDAP server.</summary>
        /// <param name="connection">The LDAP connection to authenticate against.</param>
        /// <param name="uri">The URI used for the connection, this is used for GSSAPI as the target SPN.</param>
        /// <param name="auth">The authentication mechanism to use.</param>
        /// <param name="credential">The explicit username and password to authenticate with.</param>
        /// <param name="channelBindings">TLS channel bindings to use with GSSAPI authentication.</param>
        /// <param name="transportIsTls">Whether the underlying transport is protected with TLS.</param>
        /// <param name="sessionOptions">More session options to control the auth behaviour.</param>
        /// <param name="cancelToken">Cancellation token for any network requests.</param>
        /// <param name="cmdlet">PSCmdlet to write verbose records to.</param>
        private static void Authenticate(OpenADConnection connection, Uri uri, AuthenticationMethod auth,
            PSCredential? credential, ChannelBindings? channelBindings, bool transportIsTls,
            OpenADSessionOptions sessionOptions, CancellationToken cancelToken, PSCmdlet? cmdlet)
        {
            if (auth == AuthenticationMethod.Default)
            {
                // Always favour Negotiate auth if it is available, otherwise use Simple if both a credential and the
                // exchange would be encrypted. If all else fails use an anonymous bind.
                AuthenticationProvider nego = GlobalState.Providers[AuthenticationMethod.Negotiate];
                if (nego.Available)
                {
                    auth = AuthenticationMethod.Negotiate;
                }
                else if (credential != null && transportIsTls)
                {
                    auth = AuthenticationMethod.Simple;
                }
                else
                {
                    auth = AuthenticationMethod.Anonymous;
                }

                cmdlet?.WriteVerbose($"Default authentiation mechanism has been set to {auth}");
            }

            AuthenticationProvider selectedAuth = GlobalState.Providers[auth];
            if (!selectedAuth.Available)
            {
                string msg = $"";
                if (!string.IsNullOrWhiteSpace(selectedAuth.Details))
                    msg += $" - ${selectedAuth.Details}";
                throw new ArgumentException(msg);
            }

            string username = credential?.UserName ?? "";
            string password = credential?.GetNetworkCredential().Password ?? "";

            if (auth == AuthenticationMethod.Kerberos || auth == AuthenticationMethod.Negotiate)
            {
                bool integrity = !(transportIsTls || sessionOptions.NoSigning);
                bool confidentiality = !(transportIsTls || sessionOptions.NoEncryption);

                // GSS-SPNEGO on non-Windows cannot disable confidentiality without also disabling integrity so warn
                // the caller if this set of session options have been set. Technically NTLM on Windows also applies
                // here but we cannot know what SPNEGO will choose until after the auth is done so just ignore that.
                if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows) &&
                    auth == AuthenticationMethod.Negotiate && sessionOptions.NoEncryption
                    && !sessionOptions.NoSigning)
                {
                    cmdlet?.WriteWarning("-AuthType Negotiate cannot disable encryption without disabling signing");
                    // Will be set to false above, need to ensure that it is true unless TLS is used as the packets
                    // must be encrypted for Negotiate unless both integrity is disabled.
                    confidentiality = !transportIsTls;
                }
                if (sessionOptions.NoSigning && !sessionOptions.NoEncryption)
                {
                    cmdlet?.WriteWarning("Cannot disable signatures and not encryption");
                }

                SecurityContext context;
                if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                {
                    string targetSpn = $"ldap/{uri.DnsSafeHost}";
                    context = new SspiContext(username, password, auth, targetSpn, channelBindings, integrity,
                        confidentiality);
                }
                else
                {
                    string targetSpn = $"ldap@{uri.DnsSafeHost}";
                    context = new GssapiContext(username, password, auth, targetSpn, channelBindings, integrity,
                        confidentiality);
                }
                SaslAuth(connection, context, selectedAuth.SaslId, integrity, confidentiality,
                    cancelToken);

                connection.SecurityContext = context;
                connection.Sign = integrity;
                connection.Encrypt = confidentiality;

                cmdlet?.WriteVerbose($"SASL auth complete - Will Sign {integrity} - Will Encrypt {confidentiality}");
            }
            else
            {
                SimpleAuth(connection, username, password, cancelToken);
            }
        }

        /// <summary>Performs a SIMPLE bind to the LDAP server</summary>
        /// <param name="connection">The LDAP connection to perform the bind on.</param>
        /// <param name="username">The username used for the SIMPLE bind.</param>
        /// <param name="password">The password used for the SIMPLE bind.</param>
        /// <param name="cancelToken">Token to cancel any network IO waits</param>
        private static void SimpleAuth(OpenADConnection connection, string? username, string? password,
            CancellationToken cancelToken)
        {
            int bindId = connection.Session.Bind(username ?? "", password ?? "");

            BindResponse response = (BindResponse)connection.WaitForMessage(bindId, cancelToken);
            connection.RemoveMessageQueue(bindId);
            if (response.Result.ResultCode != LDAPResultCode.Success)
            {
                throw new LDAPException(response.Result);
            }
        }

        /// <summary>Performs a SASL bind to the LDAP server</summary>
        /// <param name="connection">The LDAP connection to perform the bind on.</param>
        /// <param name="context">The security context used to generate the SASL tokens and wrap the data.</param>
        /// <param name="saslMech">The name of the SASL mechanism used</param>
        /// <param name="integrity">Whether to negotiate message signatures using the auth context.</param>
        /// <param name="confidentiality">Whether to negotiate message encryption using the auth context.</param>
        /// <param name="cancelToken">Token to cancel any network IO waits</param>
        private static void SaslAuth(OpenADConnection connection, SecurityContext context,
            string saslMech, bool integrity, bool confidentiality, CancellationToken cancelToken)
        {
            byte[]? inputToken = null;
            int saslId;

            BindResponse response;
            while (inputToken == null || inputToken.Length > 0)
            {
                byte[] outputToken = context.Step(inputToken: inputToken);
                if (outputToken.Length == 0 && context.Complete)
                    break;

                saslId = connection.Session.SaslBind("", saslMech, outputToken);

                response = (BindResponse)connection.WaitForMessage(saslId, cancelToken);
                connection.RemoveMessageQueue(saslId);
                if (response.Result.ResultCode != LDAPResultCode.Success &&
                    response.Result.ResultCode != LDAPResultCode.SaslBindInProgress)
                {
                    throw new LDAPException(response.Result);
                }

                inputToken = response.ServerSaslCreds;
            }

            // FIXME: use proper exceptions
            if (integrity && !context.IntegrityAvailable)
                throw new Exception("No integrity available on context");

            if (confidentiality && !context.ConfidentialityAvailable)
                throw new Exception("No confidentiality available on context");

            // The only SASL mech supported that does further work is the GSSAPI mech. This behaviour is defined in
            // RF 4752 - Section 3.1 - https://datatracker.ietf.org/doc/html/rfc4752#section-3.1
            if (saslMech != "GSSAPI")
                return;

            saslId = connection.Session.SaslBind("", saslMech, Array.Empty<byte>());
            response = (BindResponse)connection.WaitForMessage(saslId, cancelToken);
            connection.RemoveMessageQueue(saslId);
            if (response.Result.ResultCode != LDAPResultCode.Success &&
                response.Result.ResultCode != LDAPResultCode.SaslBindInProgress)
            {
                throw new LDAPException(response.Result);
            }

            inputToken = response.ServerSaslCreds;

            // FIXME exceptions
            if (inputToken == null)
                throw new Exception("Expecting input token to verify security context");

            byte[] contextInfo = context.Unwrap(inputToken);
            if (contextInfo.Length != 4)
                throw new Exception("Expecting input to contain 4 bytes");

            SASLSecurityFlags serverFlags = (SASLSecurityFlags)contextInfo[0];
            contextInfo[0] = 0;
            if (BitConverter.IsLittleEndian)
                Array.Reverse(contextInfo);
            uint maxServerMessageLength = BitConverter.ToUInt32(contextInfo);

            if (serverFlags == SASLSecurityFlags.NoSecurity && maxServerMessageLength != 0)
                throw new Exception("Max size must be 0 with no security");

            // Build the client flags based on what the client requests
            SASLSecurityFlags clientFlags = SASLSecurityFlags.NoSecurity;
            if (integrity && confidentiality)
                clientFlags |= SASLSecurityFlags.Confidentiality | SASLSecurityFlags.Integrity;
            else if (integrity)
                clientFlags |= SASLSecurityFlags.Integrity;

            uint maxClientMessageLength = 0;
            if (clientFlags != SASLSecurityFlags.NoSecurity)
            {
                // Windows doesn't have a max wrap size func, just send back the server value.
                maxClientMessageLength = RuntimeInformation.IsOSPlatform(OSPlatform.Windows)
                    ? maxServerMessageLength
                    : context.MaxWrapSize(maxServerMessageLength, confidentiality);
            }

            byte[] clientContextInfo = BitConverter.GetBytes(maxClientMessageLength);
            if (BitConverter.IsLittleEndian)
                Array.Reverse(clientContextInfo);
            clientContextInfo[0] = (byte)clientFlags;

            byte[] wrappedResp = context.Wrap(clientContextInfo, false);

            saslId = connection.Session.SaslBind("", saslMech, wrappedResp);
            response = (BindResponse)connection.WaitForMessage(saslId, cancelToken);
            connection.RemoveMessageQueue(saslId);
            if (response.Result.ResultCode != LDAPResultCode.Success &&
                response.Result.ResultCode != LDAPResultCode.SaslBindInProgress)
            {
                throw new LDAPException(response.Result);
            }
        }

        /// <summary>Performs an LDAP search operation.</summary>
        /// <param name="connection">The LDAP connection to perform the search on on.</param>
        /// <param name="searchBase">The search base of the query.</param>
        /// <param name="scope">The scope of the query.</param>
        /// <param name="filter">The LDAP filter to use for the query.</param>
        /// <param name="attributes">The attributes to retrieve.</param>
        /// <param name="cancelToken">Token to cancel any network IO waits</param>
        /// <returns>A dictionary of each attribute and their values as a string.</returns>
        private static Dictionary<string, string[]> LdapQuery(OpenADConnection connection, string searchBase,
            SearchScope scope, LDAPFilter filter, string[] attributes, CancellationToken cancelToken)
        {
            int searchId = connection.Session.SearchRequest(searchBase, scope, DereferencingPolicy.Never, 0, 0, false,
                filter, attributes);

            Dictionary<string, string[]> result = new();
            while (true)
            {
                LDAPMessage searchRes = connection.WaitForMessage(searchId, cancelToken);
                if (searchRes is SearchResultDone)
                    break;
                else if (searchRes is SearchResultReference)
                    continue;

                SearchResultEntry entry = (SearchResultEntry)searchRes;
                foreach (PartialAttribute attribute in entry.Attributes)
                {
                    result[attribute.Name] = attribute.Values.Select(v => Encoding.UTF8.GetString(v)).ToArray();
                }
            }
            connection.RemoveMessageQueue(searchId);

            return result;
        }

        /// <summary>Gets the attribute schema information.</summary>
        /// <param name="connection">The LDAP connection to perform the search on on.</param>
        /// <param name="subschemaSubentry">The DN of the subschemaSubentry to query.</param>
        /// <param name="cancelToken">Token to cancel any network IO waits</param>
        /// <param name="cmdlet">PSCmdlet used to write verbose records.</param>
        /// <returns>The attribute information from the parse schema information.</returns>
        private static AttributeTransformer QueryAttributeTypes(OpenADConnection connection, string subschemaSubentry,
            CancellationToken cancelToken, PSCmdlet? cmdlet)
        {
            Dictionary<string, string[]> schemaInfo = LdapQuery(connection, subschemaSubentry, SearchScope.Base,
                new FilterPresent("objectClass"), new string[] { "attributeTypes" }, cancelToken);

            Dictionary<string, AttributeTypes> attrInfo = new();
            foreach (string attributeTypes in schemaInfo["attributeTypes"])
            {
                // In testing 2 attributes (respsTo, and repsFrom) had the string value here
                string rawValue = attributeTypes;
                if (rawValue.Contains("SYNTAX 'OctetString'"))
                {
                    rawValue = rawValue.Replace("SYNTAX 'OctetString'",
                        "SYNTAX '1.3.6.1.4.1.1466.115.121.1.40");
                }

                // Neither Syntax or Name should be undefined but they are technically optional in the spec. Write a
                // verbose entry to help with future debugging if this becomes more of an issue.
                AttributeTypes attrTypes = new(rawValue);
                if (String.IsNullOrEmpty(attrTypes.Syntax))
                {
                    cmdlet?.WriteVerbose($"Failed to parse SYNTAX: '{attributeTypes}'");
                    continue;
                }
                if (String.IsNullOrEmpty(attrTypes.Name))
                {
                    cmdlet?.WriteVerbose($"Failed to parse NAME: '{attributeTypes}'");
                    continue;
                }

                attrInfo[attrTypes.Name] = attrTypes;
            }

            return new AttributeTransformer(attrInfo);
        }

        private static bool ValidateServerCertificate(object sender, X509Certificate certificate, X509Chain chain,
            SslPolicyErrors sslPolicyErrors)
        {
            return true;
        }
    }

    internal class OpenADConnection : IDisposable
    {
        private readonly Task _recvTask;
        private readonly Task _sendTask;
        private readonly ConcurrentDictionary<int, BlockingCollection<LDAPMessage>> _messages = new();
        private readonly ManualResetEventSlim _tlsReplaceEvent = new(true);
        private CancellationTokenSource _recvCancel = new();

        public TcpClient Connection { get; internal set; }
        public Stream IOStream { get; internal set; }
        public LDAPSession Session { get; set; }
        public SecurityContext? SecurityContext { get; set; }

        public bool Sign { get; set; }
        public bool Encrypt { get; set; }

        public OpenADConnection(TcpClient connection, Stream stream, LDAPSession session)
        {
            Connection = connection;
            IOStream = stream;
            Session = session;

            _recvTask = Task.Run(Recv);
            _sendTask = Task.Run(Send);
        }

        public LDAPMessage WaitForMessage(int messageId, CancellationToken cancelToken = default)
        {
            BlockingCollection<LDAPMessage> queue = _messages.GetOrAdd(messageId,
                new BlockingCollection<LDAPMessage>(new ConcurrentQueue<LDAPMessage>()));
            return queue.Take(cancelToken);
        }

        public void RemoveMessageQueue(int messageId)
        {
            _messages.TryRemove(messageId, out var _);
        }

        public SslStream SetTlsStream(SslClientAuthenticationOptions authOptions, CancellationToken cancelToken = default)
        {
            // Mark this event as unset and cancel the Recv task. This task will wait until the event is set again
            // before continuing with the replace IOStream which is the SSL context that was created.
            _tlsReplaceEvent.Reset();
            _recvCancel.Cancel();

            SslStream tls = new(IOStream, false);
            tls.AuthenticateAsClientAsync(authOptions, cancelToken).GetAwaiter().GetResult();
            IOStream = tls;

            _recvCancel = new CancellationTokenSource();
            _tlsReplaceEvent.Set();

            return tls;
        }

        private async Task Send()
        {
            PipeReader reader = Session.Outgoing;

            while (true)
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
                    // await IOStream.WriteAsync(lengthData, 0, lengthData.Length);
                    // await IOStream.WriteAsync(wrappedData, 0, wrappedData.Length);
                    ArrayPool<byte> shared = ArrayPool<byte>.Shared;
                    byte[] rentedArray = shared.Rent(wrappedData.Length + 4);
                    try
                    {
                        Buffer.BlockCopy(lengthData, 0, rentedArray, 0, lengthData.Length);
                        Buffer.BlockCopy(wrappedData, 0, rentedArray, lengthData.Length, wrappedData.Length);
                        await IOStream.WriteAsync(rentedArray, 0, lengthData.Length + wrappedData.Length);
                    }
                    finally
                    {
                        shared.Return(rentedArray);
                    }
                }
                else
                {
                    // Most likely inefficient but unsure on how to do this properly.
                    ReadOnlyMemory<byte> data = buffer.ToArray();
                    await IOStream.WriteAsync(data);
                }

                await IOStream.FlushAsync();

                reader.AdvanceTo(buffer.End);

                if (result.IsCompleted)
                    break;
            }

            await reader.CompleteAsync();
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
                Memory<byte> memory = writer.GetMemory(Connection.ReceiveBufferSize);
                try
                {
                    int bytesRead = await IOStream.ReadAsync(memory, _recvCancel.Token);
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
                    // Most likely inefficient but unsure on how to do this properly.
                    ReadOnlyMemory<byte> data = buffer.ToArray();
                    consumed = TryReadMessage(data.Span);
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

                // TODO: Handle messageId == 0 and ExtendedResponse with notice of disconnection.

                BlockingCollection<LDAPMessage> queue = _messages.GetOrAdd(message.MessageId,
                    new BlockingCollection<LDAPMessage>(new ConcurrentQueue<LDAPMessage>()));
                queue.Add(message);
            }

            return totalConsumed;
        }

        public void Dispose()
        {
            // Cancel the recv so it doesn't fail with connection reset by peer
            _recvCancel.Cancel();
            _recvTask.GetAwaiter().GetResult();

            // The unbind response also marks the LDAP outgoing reader as done
            Session.Unbind();
            _sendTask.GetAwaiter().GetResult();

            // Once both tasks are complete dispose of the stream and connection.
            IOStream.Dispose();
            Connection.Dispose();

            GC.SuppressFinalize(this);
        }
        ~OpenADConnection() { Dispose(); }
    }

    internal static class GlobalState
    {
        // Populated by OnImport
        public static Dictionary<AuthenticationMethod, AuthenticationProvider> Providers = new();

        public static string? DefaultRealm;

        public static Dictionary<string, OpenADSession> ImplicitSessions = new(StringComparer.OrdinalIgnoreCase);

        public static bool GssapiIsHeimdal;

        public static void AddSession(string id, OpenADSession session)
        {
            if (ImplicitSessions.ContainsKey(id))
                ImplicitSessions[id].Close();

            ImplicitSessions[id] = session;
        }
    }
}

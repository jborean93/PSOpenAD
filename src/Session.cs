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
            bool startTLS, OpenADSessionOptions sessionOptions, CancellationToken cancelToken = default,
            PSCmdlet? cmdlet = null)
        {
            if (GlobalState.ImplicitSessions.TryGetValue(uri.ToString(), out var session) && !session.IsClosed)
            {
                cmdlet?.WriteVerbose("Using cached OpenADSession");
                return session;
            }
            else
            {
                session = Create(uri, credential, auth, startTLS, sessionOptions, cancelToken, cmdlet: cmdlet);
                GlobalState.AddSession(uri.ToString(), session);

                return session;
            }
        }

        internal static OpenADSession Create(Uri uri, PSCredential? credential, AuthenticationMethod auth,
            bool startTLS, OpenADSessionOptions sessionOptions, CancellationToken cancelToken = default,
            PSCmdlet? cmdlet = null)
        {
            cmdlet?.WriteVerbose($"Connecting to {uri}");
            TcpClient client = new();
            Task connectTask = client.ConnectAsync(uri.DnsSafeHost, uri.Port);
            if (!connectTask.Wait(10000, cancelToken))
                throw new TimeoutException();
            connectTask.GetAwaiter().GetResult();

            OpenADConnection connection = new(client, client.GetStream(), new LDAPSession());

            bool transportIsTLS = false;
            byte[]? channelBindings = null;
            if (startTLS || uri.Scheme.Equals("ldaps", StringComparison.InvariantCultureIgnoreCase))
            {
                transportIsTLS = true;

                if (sessionOptions.NoEncryption || sessionOptions.NoSigning)
                    throw new ArgumentException("Cannot disable encryption or signatures for TLS based connection");

                if (startTLS && uri.Scheme.Equals("ldaps", StringComparison.InvariantCultureIgnoreCase))
                {
                    throw new ArgumentException("Cannot use StartTLS over an LDAPS connection");
                }
                else if (startTLS)
                {
                    int startTlsId = connection.Session.ExtendedRequest("1.3.6.1.4.1.1466.20037");
                    ExtendedResponse extResp = (ExtendedResponse)connection.WaitForMessage(startTlsId, cancelToken);
                    connection.RemoveMessageQueue(startTlsId);
                    if (extResp.Result.ResultCode != LDAPResultCode.Success)
                        throw new LDAPException(extResp.Result);
                }

                SslClientAuthenticationOptions authOptions = new()
                {
                    RemoteCertificateValidationCallback = ValidateServerCertificate,
                    TargetHost = uri.DnsSafeHost,
                };
                SslStream tls = connection.SetTlsStream(authOptions, cancelToken);

                if (!sessionOptions.NoChannelBinding)
                {
                    //cmdlet?.WriteVerbose("Attempting to get TLS channel bindings for SASL authentication");
                    channelBindings = GetTlsChannelBindings(tls);
                }
            }

            if (auth == AuthenticationMethod.Default)
            {
                // Always favour Negotiate auth if it is available, otherwise use Simple if both a credential and the
                // exchange would be encrypted. If all else fails use an anonymous bind.
                AuthenticationProvider nego = GlobalState.Providers[AuthenticationMethod.Negotiate];
                if (nego.Available)
                {
                    auth = AuthenticationMethod.Negotiate;
                }
                else if (credential != null && transportIsTLS)
                {
                    auth = AuthenticationMethod.Simple;
                }
                else
                {
                    auth = AuthenticationMethod.Anonymous;
                }
            }

            AuthenticationProvider selectedAuth = GlobalState.Providers[auth];
            if (!selectedAuth.Available)
            {
                throw new ArgumentException($"Client cannot offer -Authentication {auth} as it is not available");
            }

            string username = credential?.UserName ?? "";
            string password = credential?.GetNetworkCredential().Password ?? "";

            if (auth == AuthenticationMethod.Kerberos || auth == AuthenticationMethod.Negotiate)
            {
                string targetSpn = $"ldap@{uri.DnsSafeHost}";
                bool integrity = !(transportIsTLS || sessionOptions.NoSigning);
                bool confidentiality = !(transportIsTLS || sessionOptions.NoEncryption);

                GssapiContext context = new(username, password, auth, targetSpn, channelBindings,
                    integrity, confidentiality);
                SaslAuth(connection, context, selectedAuth.NativeId, integrity, confidentiality,
                    cancelToken);
                connection.SecurityContext = context;
                connection.Sign = integrity;
                connection.Encrypt = confidentiality;
            }
            else
            {
                SimpleAuth(connection, username, password, cancelToken);
            }

            // ldap.ExtendedRequest("1.3.6.1.4.1.4203.1.11.3");
            // await connection.Write(ldap.DataToSend(), cancelToken);
            // ExtendedResponse whoamiResp = (ExtendedResponse)await connection.Read(ldap, cancelToken);
            // if (whoamiResp.Result.ResultCode != LDAPResultCode.Success)
            //     throw new LDAPException(whoamiResp.Result);

            // string whoami = Encoding.UTF8.GetString(whoamiResp.Value ?? Array.Empty<byte>());
            // Console.WriteLine($"User {whoami}");

            // Attempt to get the default naming context.
            Dictionary<string, string[]> rootInfo = LdapQuery(connection, "", SearchScope.Base,
                "(objectClass=*)", new string[] { "defaultNamingContext", "subschemaSubentry" }, cancelToken);

            // While AD should have this some LDAP servers do not, just try with no base value.
            string defaultNamingContext = "";
            if (rootInfo.ContainsKey("defaultNamingContext"))
                defaultNamingContext = (rootInfo["defaultNamingContext"] ?? new string[] { "" })[0];

            string subschemaSubentry = rootInfo["subschemaSubentry"][0];

            // Attempt to get the schema info of the host so the code can parse the raw LDAP attribute values into the
            // required PowerShell type.
            // These attributes are from the below but so far the code only uses the uncommented one.
            // https://ldapwiki.com/wiki/LDAP%20Query%20For%20Schema
            string[] schemaAttributes = new string[]
            {
                "attributeTypes",
                //"dITStructureRules",
                //"objectClasses",
                //"nameForms",
                //"dITContentRules",
                //"matchingRules",
                //"ldapSyntaxes",
                //"matchingRuleUse",
            };
            Dictionary<string, string[]> schemaInfo = LdapQuery(connection, subschemaSubentry, SearchScope.Base,
                "(objectClass=*)", schemaAttributes, cancelToken);

            // foreach (string objectClass in schemaInfo["objectClasses"])
            // {
            //     ObjectClassDefinition def = new ObjectClassDefinition(objectClass);
            // }

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
                // debug entry to help with future debugging if this becomes more of an issue.
                AttributeTypes attrTypes = new(rawValue);
                if (String.IsNullOrEmpty(attrTypes.Syntax))
                {
                    Console.WriteLine($"DEBUG: Failed to parse SYNTAX: '{attributeTypes}'");
                    continue;
                }
                if (String.IsNullOrEmpty(attrTypes.Name))
                {
                    Console.WriteLine($"DEBUG: Failed to parse NAME: '{attributeTypes}'");
                    continue;
                }

                attrInfo[attrTypes.Name] = attrTypes;
            }

            return new OpenADSession(connection, uri, auth, transportIsTLS || connection.Sign,
                transportIsTLS || connection.Encrypt, defaultNamingContext ?? "", new AttributeTransformer(attrInfo));
        }

        private static Dictionary<string, string[]> LdapQuery(OpenADConnection connection, string searchBase,
            SearchScope scope, string filter, string[] attributes, CancellationToken cancelToken)
        {
            LDAPFilter ldapFilter = LDAPFilter.ParseFilter(filter, 0, filter.Length, out var _);
            int searchId = connection.Session.SearchRequest(searchBase, scope, DereferencingPolicy.Never, 0, 0, false,
                ldapFilter, attributes);

            Dictionary<string, string[]> result = new();
            while (true)
            {
                LDAPMessage searchRes = connection.WaitForMessage(searchId, cancelToken);
                if (searchRes is ExtendedResponse failResp)
                    throw new LDAPException(failResp.Result);
                else if (searchRes is SearchResultDone)
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

        private static byte[]? GetTlsChannelBindings(SslStream tls)
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

            return finalCB;
        }

        private static bool ValidateServerCertificate(object sender, X509Certificate certificate, X509Chain chain,
            SslPolicyErrors sslPolicyErrors)
        {
            return true;
        }

        private static void SimpleAuth(OpenADConnection connection, string? username, string? password,
            CancellationToken cancelToken)
        {
            int bindId = connection.Session.Bind(username ?? "", password ?? "");

            BindResponse response = (BindResponse)connection.WaitForMessage(bindId, cancelToken);
            connection.RemoveMessageQueue(bindId);
            if (response.Result.ResultCode != LDAPResultCode.Success &&
                response.Result.ResultCode != LDAPResultCode.SaslBindInProgress)
            {
                throw new LDAPException(response.Result);
            }
        }

        private static void SaslAuth(OpenADConnection connection, SecurityContext context,
            string saslMech, bool integrity, bool confidentiality, CancellationToken cancelToken)
        {
            byte[]? inputToken = null;
            int saslId;

            BindResponse response;
            while (true)
            {
                byte[] outputToken = context.Step(inputToken: inputToken);
                if (context.Complete)
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

            if (inputToken == null)
                throw new Exception("Expecting input token to verify security context");

            byte[] contextInfo = context.Unwrap(inputToken);
            if (contextInfo.Length != 4)
                throw new Exception("Expecting input to contain 4 bytes");

            SASLSecurityFlags flags = (SASLSecurityFlags)inputToken[0];
            byte[] maxServerBytes = new byte[4];
            Array.Copy(inputToken, 1, maxServerBytes, 0, 3);
            if (BitConverter.IsLittleEndian)
                Array.Reverse(maxServerBytes);
            uint maxServerMessageLength = BitConverter.ToUInt32(maxServerBytes);

            if (flags == SASLSecurityFlags.NoSecurity && maxServerMessageLength != 0)
                throw new Exception("Max size must be 0 with no security");

            SASLSecurityFlags clientFlags = SASLSecurityFlags.NoSecurity;
            if (integrity && confidentiality)
                clientFlags |= SASLSecurityFlags.Confidentiality | SASLSecurityFlags.Integrity;
            else if (integrity)
                clientFlags |= SASLSecurityFlags.Integrity;

            uint maxClientMessageLength = 0;
            if (clientFlags != SASLSecurityFlags.NoSecurity)
            {
                bool confReq = (clientFlags & SASLSecurityFlags.Confidentiality) != 0;
                maxClientMessageLength = context.MaxWrapSize(maxServerMessageLength, confReq);
            }

            byte[] clientContextInfo = BitConverter.GetBytes(maxClientMessageLength);
            Array.Reverse(clientContextInfo);
            clientContextInfo[0] = (byte)clientFlags;
            byte[] saslMechBytes = Encoding.UTF8.GetBytes("");

            byte[] clientResp = new byte[clientContextInfo.Length + saslMechBytes.Length];
            Array.Copy(clientContextInfo, clientResp, clientContextInfo.Length);
            Array.Copy(saslMechBytes, 0, clientResp, clientContextInfo.Length, saslMechBytes.Length);
            byte[] wrappedResp = context.Wrap(clientResp, false);

            saslId = connection.Session.SaslBind("", saslMech, wrappedResp);
            response = (BindResponse)connection.WaitForMessage(saslId, cancelToken);
            connection.RemoveMessageQueue(saslId);
            if (response.Result.ResultCode != LDAPResultCode.Success &&
                response.Result.ResultCode != LDAPResultCode.SaslBindInProgress)
            {
                throw new LDAPException(response.Result);
            }
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

                    await IOStream.WriteAsync(lengthData, 0, lengthData.Length);
                    await IOStream.WriteAsync(wrappedData, 0, wrappedData.Length);
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
            Pipe pipe = new(new PipeOptions(pauseWriterThreshold: 0));

            Task socketReader = RecvSocket(pipe.Writer);
            Task messageProcessor = RecvProcess(pipe.Reader);
            await Task.WhenAll(socketReader, messageProcessor);
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
                else if (SecurityContext != null && Sign)
                {
                    consumed = TryReadSealedMessage(SecurityContext, buffer);
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

        private int TryReadSealedMessage(SecurityContext context, ReadOnlySequence<byte> data)
        {
            if (data.Length < 4)
                return 0;

            ReadOnlySequence<byte> lengthSequence = data.Slice(0, 4);
            Span<byte> rawLength = stackalloc byte[4];
            lengthSequence.CopyTo(rawLength);
            if (BitConverter.IsLittleEndian)
                rawLength.Reverse();

            int length = BitConverter.ToInt32(rawLength);
            if (data.Length < 4 + length)
                return 0;

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

            ReadOnlySpan<byte> unwrappedSpan = unwrappedData.AsSpan();
            while (true)
            {
                int msgConsumed = TryReadMessage(unwrappedSpan);
                if (msgConsumed == 0)
                {
                    if (unwrappedSpan.Length > 0)
                        throw new Exception("TODO Verify whether this can happen");

                    break;
                }

                unwrappedSpan = unwrappedSpan[msgConsumed..];
            }

            return 4 + length;
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

        public static void AddSession(string id, OpenADSession session)
        {
            if (ImplicitSessions.ContainsKey(id))
                ImplicitSessions[id].Close();

            ImplicitSessions[id] = session;
        }
    }
}

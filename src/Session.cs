using PSOpenAD.LDAP;
using System;
using System.Buffers;
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

        public bool IsClosed { get; internal set; } = false;

        internal OpenADConnection Connection { get; }

        internal LDAPSession Ldap { get; }

        internal AttributeTransformer AttributeTransformer { get; }

        internal OpenADSession(OpenADConnection connection, LDAPSession session, Uri uri, AuthenticationMethod auth,
            bool isSigned, bool isEncrypted, string defaultNamingContext, AttributeTransformer transformer)
        {
            Connection = connection;
            Ldap = session;
            Uri = uri;
            Authentication = auth;
            IsSigned = isSigned;
            IsEncrypted = isEncrypted;
            DefaultNamingContext = defaultNamingContext;
            AttributeTransformer = transformer;
        }

        internal void Close()
        {
            Ldap.Unbind();
            Connection.WriteAsync(Ldap.DataToSend()).GetAwaiter().GetResult();
            Connection.Dispose();
            IsClosed = true;
        }
    }

    internal sealed class OpenADSessionFactory
    {
        internal async static Task<OpenADSession> CreateOrUseDefaultAsync(Uri uri, PSCredential? credential,
            AuthenticationMethod auth, bool startTLS, OpenADSessionOptions sessionOptions,
            CancellationToken cancelToken = default)
        {
            if (GlobalState.ImplicitSessions.TryGetValue(uri.ToString(), out var session) && !session.IsClosed)
            {
                return session;
            }
            else
            {
                session = await CreateAsync(uri, credential, auth, startTLS, sessionOptions, cancelToken);
                GlobalState.AddSession(uri.ToString(), session);

                return session;
            }
        }

        internal async static Task<OpenADSession> CreateAsync(Uri uri, PSCredential? credential,
            AuthenticationMethod auth, bool startTLS, OpenADSessionOptions sessionOptions,
            CancellationToken cancelToken = default)
        {
            TcpClient client = new TcpClient();
            Task connectTask = client.ConnectAsync(uri.DnsSafeHost, uri.Port);
            if (!connectTask.Wait(10000, cancelToken))
                throw new TimeoutException();

            OpenADConnection connection = new OpenADConnection(client, client.GetStream());
            LDAPSession ldap = new LDAPSession();

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
                    ldap.ExtendedRequest("1.3.6.1.4.1.1466.20037"); // StartTLS
                    await connection.WriteAsync(ldap.DataToSend(), cancelToken);

                    ExtendedResponse extResp = (ExtendedResponse)await connection.ReadAsync(ldap, cancelToken);
                    if (extResp.Result.ResultCode != LDAPResultCode.Success)
                        throw new LDAPException(extResp.Result);
                }

                SslClientAuthenticationOptions authOptions = new SslClientAuthenticationOptions()
                {
                    RemoteCertificateValidationCallback = ValidateServerCertificate,
                    TargetHost = uri.DnsSafeHost,
                };
                SslStream tls = new SslStream(connection.IOStream, false);
                await tls.AuthenticateAsClientAsync(authOptions, cancelToken);
                connection.IOStream = tls;

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

                GssapiContext context = new GssapiContext(username, password, auth, targetSpn, channelBindings,
                    integrity, confidentiality);
                await SaslAuth(connection, ldap, context, selectedAuth.NativeId, integrity, confidentiality,
                    cancelToken);
                connection.SecurityContext = context;
                connection.Sign = integrity;
                connection.Encrypt = confidentiality;
            }
            else
            {
                await SimpleAuth(connection, ldap, username, password, cancelToken);
            }

            // ldap.ExtendedRequest("1.3.6.1.4.1.4203.1.11.3");
            // await connection.WriteAsync(ldap.DataToSend(), cancelToken);
            // ExtendedResponse whoamiResp = (ExtendedResponse)await connection.ReadAsync(ldap, cancelToken);
            // if (whoamiResp.Result.ResultCode != LDAPResultCode.Success)
            //     throw new LDAPException(whoamiResp.Result);

            // string whoami = Encoding.UTF8.GetString(whoamiResp.Value ?? Array.Empty<byte>());
            // Console.WriteLine($"User {whoami}");

            // Attempt to get the default naming context.
            Dictionary<string, string[]> rootInfo = await LdapQuery(connection, ldap, "", SearchScope.Base,
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
            Dictionary<string, string[]> schemaInfo = await LdapQuery(connection, ldap, subschemaSubentry,
                SearchScope.Base, "(objectClass=*)", schemaAttributes, cancelToken);

            // foreach (string objectClass in schemaInfo["objectClasses"])
            // {
            //     ObjectClassDefinition def = new ObjectClassDefinition(objectClass);
            // }

            Dictionary<string, AttributeTypes> attrInfo = new Dictionary<string, AttributeTypes>();
            foreach (string attributeTypes in schemaInfo["attributeTypes"])
            {
                // In testing 2 attributes (respsTo, and repsFrom) had the string value here
                if (attributeTypes.Contains("SYNTAX 'OctetString'"))
                    attributeTypes.Replace("SYNTAX 'OctetString'", "SYNTAX '1.3.6.1.4.1.1466.115.121.1.40");

                // Neither Syntax or Name should be undefined but they are technically optional in the spec. Write a
                // debug entry to help with future debugging if this becomes more of an issue.
                AttributeTypes attrTypes = new AttributeTypes(attributeTypes);
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

            return new OpenADSession(connection, ldap, uri, auth, transportIsTLS || connection.Sign,
                transportIsTLS || connection.Encrypt, defaultNamingContext ?? "", new AttributeTransformer(attrInfo));
        }

        private async static Task<Dictionary<string, string[]>> LdapQuery(OpenADConnection connection,
            LDAPSession ldap, string searchBase, SearchScope scope, string filter, string[] attributes,
            CancellationToken cancelToken)
        {
            LDAPFilter ldapFilter = LDAPFilter.ParseFilter(filter, 0, filter.Length, out var _);
            ldap.SearchRequest(searchBase, scope, DereferencingPolicy.Never, 0, 0, false, ldapFilter, attributes);
            await connection.WriteAsync(ldap.DataToSend(), cancelToken);

            Dictionary<string, string[]> result = new Dictionary<string, string[]>();
            while (true)
            {
                LDAPMessage searchRes = await connection.ReadAsync(ldap, cancelToken);
                if (searchRes is ExtendedResponse failResp)
                    throw new LDAPException(failResp.Result);
                else if (searchRes is SearchResultDone)
                    break;

                SearchResultEntry entry = (SearchResultEntry)searchRes;
                foreach (PartialAttribute attribute in entry.Attributes)
                {
                    result[attribute.Name] = attribute.Values.Select(v => Encoding.UTF8.GetString(v)).ToArray();
                }
            }

            return result;
        }

        private static byte[]? GetTlsChannelBindings(SslStream tls)
        {
            using X509Certificate2 cert = new X509Certificate2(tls.RemoteCertificate);

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
            SslPolicyErrors sslPolicyErrors) => true;

        private static async Task SimpleAuth(OpenADConnection connection, LDAPSession ldap, string? username,
            string? password, CancellationToken cancelToken)
        {
            ldap.Bind(username ?? "", password ?? "");

            await connection.WriteAsync(ldap.DataToSend(), cancelToken);
            BindResponse response = (BindResponse)await connection.ReadAsync(ldap, cancelToken);
            if (response.Result.ResultCode != LDAPResultCode.Success &&
                response.Result.ResultCode != LDAPResultCode.SaslBindInProgress)
            {
                throw new LDAPException(response.Result);
            }
        }

        private static async Task SaslAuth(OpenADConnection connection, LDAPSession ldap, SecurityContext context,
            string saslMech, bool integrity, bool confidentiality, CancellationToken cancelToken)
        {
            byte[]? inputToken = null;
            BindResponse response;
            while (true)
            {
                byte[] outputToken = context.Step(inputToken: inputToken);
                if (context.Complete)
                    break;

                ldap.SaslBind("", saslMech, outputToken);
                await connection.WriteAsync(ldap.DataToSend(), cancelToken);

                response = (BindResponse)await connection.ReadAsync(ldap, cancelToken);
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

            ldap.SaslBind("", saslMech, Array.Empty<byte>());
            await connection.WriteAsync(ldap.DataToSend(), cancelToken);
            response = (BindResponse)await connection.ReadAsync(ldap, cancelToken);
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

            ldap.SaslBind("", saslMech, wrappedResp);
            await connection.WriteAsync(ldap.DataToSend(), cancelToken);
            response = (BindResponse)await connection.ReadAsync(ldap, cancelToken);
            if (response.Result.ResultCode != LDAPResultCode.Success &&
                response.Result.ResultCode != LDAPResultCode.SaslBindInProgress)
            {
                throw new LDAPException(response.Result);
            }
        }
    }

    internal class OpenADConnection : IDisposable
    {
        public TcpClient Connection { get; internal set; }
        public Stream IOStream { get; internal set; }
        public SecurityContext? SecurityContext { get; set; }

        public bool Sign { get; set; }
        public bool Encrypt { get; set; }

        public OpenADConnection(TcpClient connection, Stream stream)
        {
            Connection = connection;
            IOStream = stream;
        }

        public async Task WriteAsync(byte[] data, CancellationToken cancelToken = default)
        {
            if (SecurityContext != null && Sign)
            {
                byte[] wrappedData = SecurityContext.Wrap(data, Encrypt);
                byte[] lengthData = BitConverter.GetBytes(wrappedData.Length);
                if (BitConverter.IsLittleEndian)
                    Array.Reverse(lengthData);

                data = new byte[wrappedData.Length + lengthData.Length];
                Array.Copy(lengthData, 0, data, 0, lengthData.Length);
                Array.Copy(wrappedData, 0, data, lengthData.Length, wrappedData.Length);
            }

            await IOStream.WriteAsync(data, 0, data.Length, cancelToken);
        }

        public async Task<LDAPMessage> ReadAsync(LDAPSession session, CancellationToken cancelToken = default)
        {
            PipeWriter target = session.Incoming;

            while (true)
            {
                LDAPMessage? message = session.NextEvent();
                if (message != null)
                    return message;

                int bytesRead;
                if (SecurityContext != null && Sign)
                {
                    byte[] wrappedData = await ReadWrappedAsync(cancelToken);

                    ReadOnlyMemory<byte> unwrappedData = SecurityContext.Unwrap(wrappedData);
                    Memory<byte> memory = target.GetMemory(unwrappedData.Length);
                    unwrappedData.CopyTo(memory);

                    bytesRead = unwrappedData.Length;
                }
                else
                {
                    Memory<byte> memory = target.GetMemory(Connection.ReceiveBufferSize);
                    bytesRead = await IOStream.ReadAsync(memory, cancelToken);
                }

                target.Advance(bytesRead);
                await target.FlushAsync();
            }
        }

        private async Task<byte[]> ReadWrappedAsync(CancellationToken cancelToken)
        {
            Pipe pipeline = new Pipe();

            // The first 4 bytes is the length of the wrapped message. This will be updated once those bytes have been
            // read.
            int bytesNeeded = 4;
            int bytesRead = 0;
            int bufferSize = Connection.ReceiveBufferSize;
            while (bytesRead < bytesNeeded)
            {
                Memory<byte> wrappedMemory = pipeline.Writer.GetMemory(bufferSize);

                bytesRead += await IOStream.ReadAsync(wrappedMemory, cancelToken);
                pipeline.Writer.Advance(bytesRead);

                if (bytesNeeded == 4 && bytesRead >= 4)
                {
                    await pipeline.Writer.FlushAsync();

                    ReadResult res = await pipeline.Reader.ReadAtLeastAsync(4);
                    byte[] rawNeeded = new byte[4];
                    res.Buffer.Slice(0, 4).CopyTo(rawNeeded);
                    if (BitConverter.IsLittleEndian)
                        Array.Reverse(rawNeeded);

                    bytesNeeded += BitConverter.ToInt32(rawNeeded);
                    bufferSize = Math.Min(bytesNeeded - 4, bufferSize);
                    pipeline.Reader.AdvanceTo(res.Buffer.Slice(4).Start);
                }
            }

            await pipeline.Writer.FlushAsync();
            ReadResult wrappedRead = await pipeline.Reader.ReadAtLeastAsync(bytesNeeded - 4);
            return wrappedRead.Buffer.ToArray();
        }

        public void Dispose()
        {
            IOStream.Dispose();
            Connection.Dispose();
            GC.SuppressFinalize(this);
        }
        ~OpenADConnection() { Dispose(); }
    }


    internal static class GlobalState
    {
        // Populated by OnImport
        public static Dictionary<AuthenticationMethod, AuthenticationProvider> Providers =
            new Dictionary<AuthenticationMethod, AuthenticationProvider>();

        public static string? DefaultRealm = null;

        public static Dictionary<string, OpenADSession> ImplicitSessions = new Dictionary<string, OpenADSession>(StringComparer.OrdinalIgnoreCase);

        public static void AddSession(string id, OpenADSession session)
        {
            if (ImplicitSessions.ContainsKey(id))
                ImplicitSessions[id].Close();

            ImplicitSessions[id] = session;
        }
    }
}

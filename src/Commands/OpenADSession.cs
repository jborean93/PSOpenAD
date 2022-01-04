using PSOpenAD.LDAP;
using System;
using System.Buffers;
using System.Collections.Generic;
using System.Security.Authentication.ExtendedProtection;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.IO;
using System.IO.Pipelines;
using System.Management.Automation;
using System.Net.Security;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace PSOpenAD.Commands
{
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

        public async Task WriteAsync(byte[] data, CancellationToken cancelToken)
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

        public async Task<LDAPMessage> ReadAsync(LDAPSession session, CancellationToken cancelToken)
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

        public async Task<byte[]> ReadWrappedAsync(CancellationToken cancelToken)
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

    [Cmdlet(
        VerbsCommon.New, "OpenADSession",
        DefaultParameterSetName = "ComputerName"
    )]
    [OutputType(typeof(OpenADSession))]
    public class NewOpenADSession : PSCmdlet
    {
        [Parameter(
            Mandatory = true,
            Position = 0,
            ValueFromPipelineByPropertyName = true,
            ParameterSetName = "Uri"
        )]
        public Uri Uri { get; set; } = new Uri("ldap://default"); // dummy value used to satisfy the null reference warnings

        [Parameter(
            Mandatory = true,
            Position = 0,
            ValueFromPipeline = true,
            ValueFromPipelineByPropertyName = true,
            ParameterSetName = "ComputerName"
        )]
        [ValidateNotNullOrEmpty]
        [Alias("Server")]
        public string ComputerName { get; set; } = "";

        [Parameter(
            ParameterSetName = "ComputerName"
        )]
        public int Port { get; set; }

        [Parameter(
            ParameterSetName = "ComputerName"
        )]
        public SwitchParameter UseSSL { get; set; }

        [Parameter()]
        public PSCredential? Credential { get; set; }

        [Parameter()]
        public AuthenticationMethod AuthType { get; set; } = AuthenticationMethod.Default;

        [Parameter()]
        public SwitchParameter StartTLS { get; set; }

        [Parameter()]
        public OpenADSessionOptions SessionOption { get; set; } = new OpenADSessionOptions();

        private CancellationTokenSource? CurrentCancelToken { get; set; }

        protected override void ProcessRecord()
        {
            if (ParameterSetName == "ComputerName")
            {
                string scheme = UseSSL ? "ldaps" : "ldap";
                int port = Port != 0 ? Port : (UseSSL ? 636 : 389);
                Uri = new Uri($"{scheme}://{ComputerName}:{port}");
            }

            using (CurrentCancelToken = new CancellationTokenSource())
            {
                CreateSession(Uri, Credential, AuthType, StartTLS, SessionOption, CurrentCancelToken.Token, this
                    ).GetAwaiter().GetResult();
            }

            // using (CurrentCancelToken = new CancellationTokenSource())
            // {
            //     try
            //     {
            //         OpenADSession session = OpenADSessionFactory.Create(Uri, Credential, AuthType, StartTLS,
            //             SessionOption, this, CurrentCancelToken.Token);
            //         GlobalState.AddSession(Uri.ToString(), session);
            //         WriteObject(session);
            //     }
            //     catch (LDAPException e)
            //     {
            //         WriteError(new ErrorRecord(e, "LDAPError", ErrorCategory.ProtocolError, null));
            //     }
            //     catch (GSSAPIException e)
            //     {
            //         WriteError(new ErrorRecord(e, "GSSAPIError", ErrorCategory.ProtocolError, null));
            //     }
            //     catch (ArgumentException e)
            //     {
            //         WriteError(new ErrorRecord(e, "InvalidParameter", ErrorCategory.InvalidArgument, null));
            //     }
            // }
        }

        private async Task CreateSession(Uri uri, PSCredential? credential, AuthenticationMethod auth, bool startTLS,
            OpenADSessionOptions sessionOptions, CancellationToken cancelToken, PSCmdlet? cmdlet = null)
        {
            cmdlet?.WriteVerbose($"Connecting to LDAP host at {uri}");
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
                    cmdlet?.WriteVerbose("Running StartTLS on the LDAP connection");
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

            string username = credential?.UserName ?? "";
            string password = credential?.GetNetworkCredential().Password ?? "";
            string targetSpn = $"ldap@{uri.DnsSafeHost}";

            if (auth == AuthenticationMethod.Kerberos || auth == AuthenticationMethod.Negotiate)
            {
                bool integrity = !(transportIsTLS || sessionOptions.NoSigning);
                bool confidentiality = !(transportIsTLS || sessionOptions.NoEncryption);

                GssapiContext context = new GssapiContext(username, password, auth, targetSpn, channelBindings,
                    integrity, confidentiality);
                string saslMech = auth == AuthenticationMethod.Negotiate ? "GSS-SPNEGO" : "GSSAPI";
                await SaslAuth(connection, ldap, context, saslMech, integrity, confidentiality, cancelToken);
                connection.SecurityContext = context;
                connection.Sign = integrity;
                connection.Encrypt = confidentiality;
            }
            else
            {
                await SimpleAuth(connection, ldap, username, password, cancelToken);
            }

            ldap.ExtendedRequest("1.3.6.1.4.1.4203.1.11.3");
            await connection.WriteAsync(ldap.DataToSend(), cancelToken);
            ExtendedResponse whoamiResp = (ExtendedResponse)await connection.ReadAsync(ldap, cancelToken);
            if (whoamiResp.Result.ResultCode != LDAPResultCode.Success)
                throw new LDAPException(whoamiResp.Result);

            string whoami = Encoding.UTF8.GetString(whoamiResp.Value ?? Array.Empty<byte>());
            Console.WriteLine($"User {whoami}");

            ldap.SearchRequest("", SearchScope.Base, DereferencingPolicy.Never, 0, 0, false, "",
                new List<string>() { "defaultNamingContext", "subschemaEntry" });

            // Dictionary<string, string[]> rootInfo = LdapQuery(ldap, "", LDAPSearchScope.LDAP_SCOPE_BASE, null,
            //     new string[] { "defaultNamingContext", "subschemaSubentry" });

            ldap.Unbind();
            byte[] unbindData = ldap.DataToSend();
            await connection.WriteAsync(unbindData, cancelToken);
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

        private async Task SimpleAuth(OpenADConnection connection, LDAPSession ldap, string? username, string? password,
            CancellationToken cancelToken)
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

        private async Task SaslAuth(OpenADConnection connection, LDAPSession ldap, SecurityContext context,
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

        protected override void StopProcessing()
        {
            CurrentCancelToken?.Cancel();
        }
    }

    [Cmdlet(
        VerbsCommon.Remove, "OpenADSession"
    )]
    public class RemoveOpenADSession : PSCmdlet
    {
        [Parameter(
            Mandatory = true,
            Position = 0,
            ValueFromPipeline = true,
            ValueFromPipelineByPropertyName = true
        )]
        public OpenADSession[] Session { get; set; } = Array.Empty<OpenADSession>();

        protected override void ProcessRecord()
        {
            foreach (OpenADSession s in Session)
            {
                WriteVerbose($"Closing connection to {s.Uri}");
                s.Close();
            }
        }
    }
}

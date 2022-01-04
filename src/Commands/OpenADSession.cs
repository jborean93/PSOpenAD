using PSOpenAD.LDAP;
using System;
using System.Buffers;
using System.IO;
using System.IO.Pipelines;
using System.Management.Automation;
using System.Net.Sockets;
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
                CreateSession(Uri.Host, Uri.Port, CurrentCancelToken.Token, SessionOption).GetAwaiter().GetResult();
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

        private async Task CreateSession(string hostname, int port, CancellationToken cancelToken,
            OpenADSessionOptions sessionOptions)
        {
            TcpClient client = new TcpClient();
            Task connectTask = client.ConnectAsync(hostname, port);
            if (!connectTask.Wait(10000, cancelToken))
                throw new TimeoutException();

            OpenADConnection connection = new OpenADConnection(client, client.GetStream());
            LDAPSession ldap = new LDAPSession();

            string username = "vagrant-domain@DOMAIN.TEST";
            string password = "VagrantPass1";
            string targetSpn = $"ldap@{hostname}";

            if (AuthType == AuthenticationMethod.Kerberos || AuthType == AuthenticationMethod.Negotiate)
            {
                bool integrity = !sessionOptions.NoSigning;
                bool confidentiality = !sessionOptions.NoEncryption;

                GssapiContext context = new GssapiContext(username, password, AuthType, targetSpn, null, integrity,
                    confidentiality);
                string saslMech = AuthType == AuthenticationMethod.Negotiate ? "GSS-SPNEGO" : "GSSAPI";
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
            ExtendedResponse extResp = (ExtendedResponse)await connection.ReadAsync(ldap, cancelToken);
            if (extResp.Result.ResultCode != LDAPResultCode.Success)
                throw new LDAPException(extResp.Result);

            string whoami = Encoding.UTF8.GetString(extResp.Value ?? Array.Empty<byte>());
            Console.WriteLine($"User {whoami}");

            ldap.Unbind();
            byte[] unbindData = ldap.DataToSend();
            await connection.WriteAsync(unbindData, cancelToken);
        }

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

using PSOpenAD.Native;
using System;
using System.Buffers;
using System.Collections.Generic;
using System.Runtime.InteropServices;

namespace PSOpenAD
{
    public enum AuthenticationMethod
    {
        /// <summary>Selects the best auth mechanism available.</summary>
        Default,

        /// <summary>No authentication.</summary>
        Anonymous,

        /// <summary>
        /// Simple auth with a plaintext username and password, should only be used with LDAPS or StartTLS.
        /// </summary>
        Simple,

        /// <summary>GSSAPI/SSPI Negotiate (SASL GSS-SPNEGO) authentication.</summary>
        Negotiate,

        /// <summary>GSSAPI/SSPI Kerberos (SASL GSSAPI) authentication</summary>
        Kerberos,
    }

    /// <summary>Details on an authentication mechanism for the local client.</summary>
    public sealed class AuthenticationProvider
    {
        /// <summary>The authentication mechanism this represents.</summary>
        public AuthenticationMethod Method { get; }

        /// <summary>The SASL mechanism identifier for this provider.</summary>
        public string SaslId { get; }

        /// <summary>Whether the client can use this provider.</summary>
        public bool Available { get; }

        /// <summary>Whether this authentication mechanism can sign/encrypt data over a non-TLS connection.</summary>
        public bool CanSign { get; }

        /// <summary>Further details on why the mechanism is not available.</summary>
        public string Details { get; }

        public AuthenticationProvider(AuthenticationMethod method, string saslId, bool available, bool canSign,
            string details)
        {
            Method = method;
            SaslId = saslId;
            Available = available;
            CanSign = canSign;
            Details = details;
        }
    }

    [Flags]
    internal enum SASLSecurityFlags : byte
    {
        None = 0,
        NoSecurity = 1,
        Integrity = 2,
        Confidentiality = 4,
    }

    internal class ChannelBindings
    {
        public int InitiatorAddrType { get; set; }
        public byte[]? InitiatorAddr { get; set; }
        public int AcceptorAddrType { get; set; }
        public byte[]? AcceptorAddr { get; set; }
        public byte[]? ApplicationData { get; set; }
    }

    internal abstract class SecurityContext : IDisposable
    {
        public bool Complete { get; internal set; }
        public bool IntegrityAvailable { get; internal set; }
        public bool ConfidentialityAvailable { get; internal set; }

        public abstract byte[] Step(byte[]? inputToken = null);
        public abstract byte[] Wrap(ReadOnlySpan<byte> data, bool encrypt);
        public abstract byte[] Unwrap(ReadOnlySpan<byte> data);

        public abstract UInt32 MaxWrapSize(UInt32 outputSize, bool confReq);

        public abstract void Dispose();
        ~SecurityContext() => Dispose();
    }

    internal class GssapiContext : SecurityContext
    {
        private readonly SafeGssapiCred? _credential;
        private readonly SafeGssapiName _targetSpn;
        private readonly ChannelBindings? _bindingData;
        private readonly byte[] _mech;
        private readonly GssapiContextFlags _flags = GssapiContextFlags.GSS_C_MUTUAL_FLAG |
            GssapiContextFlags.GSS_C_SEQUENCE_FLAG;
        private SafeGssapiSecContext? _context;

        public GssapiContext(string? username, string? password, AuthenticationMethod method, string target,
            ChannelBindings? channelBindings, bool integrity, bool confidentiality)
        {
            _bindingData = channelBindings;
            _mech = method == AuthenticationMethod.Negotiate ? GSSAPI.SPNEGO : GSSAPI.KERBEROS;
            _targetSpn = GSSAPI.ImportName(target, GSSAPI.GSS_C_NT_HOSTBASED_SERVICE);

            // FIXME: Determine the rules for Heimdal, should I also specify NTLM.
            List<byte[]> mechList;
            if (GlobalState.GssapiIsHeimdal)
            {
                mechList = new List<byte[]>() { GSSAPI.KERBEROS };
            }
            else
            {
                mechList = new List<byte[]>() { _mech };
            }
            if (!string.IsNullOrEmpty(username) && !string.IsNullOrEmpty(password))
            {
                using SafeGssapiName name = GSSAPI.ImportName(username, GSSAPI.GSS_C_NT_USER_NAME);
                _credential = GSSAPI.AcquireCredWithPassword(name, password, 0, mechList,
                    GssapiCredUsage.GSS_C_INITIATE).Creds;
            }
            else
            {
                SafeGssapiName? name = null;
                if (!string.IsNullOrEmpty(username))
                    name = GSSAPI.ImportName(username, GSSAPI.GSS_C_NT_USER_NAME);

                using (name)
                    _credential = GSSAPI.AcquireCred(name, 0, mechList, GssapiCredUsage.GSS_C_INITIATE).Creds;
            }

            if (integrity)
                _flags |= GssapiContextFlags.GSS_C_INTEG_FLAG;

            if (confidentiality)
                _flags |= GssapiContextFlags.GSS_C_INTEG_FLAG | GssapiContextFlags.GSS_C_CONF_FLAG;

            if (method == AuthenticationMethod.Kerberos)
            {
                // Kerberos uses a special SASL wrapping mechanism and always requires integrity
                _flags |= GssapiContextFlags.GSS_C_INTEG_FLAG;
            }
            else if (!integrity && !confidentiality)
            {
                // GSSAPI always sets INTEG | CONF unless this flag is set. When using GSS-SPNEGO over TLS Windows
                // will reject the auth as you cannot nested wrapping within TLS. By setting this flag GSSAPI will no
                // longer add the integrity of conf flags to the auth mechanism allowing it to work with Windows.
                // Note: This does not apply to Kerberos (SASL GSSAPI) as there are futher token exchanges after the
                // auth to negotiate the integrity/conf options.
                GSSAPI.SetCredOption(_credential, GSSAPI.GSS_KRB5_CRED_NO_CI_FLAGS_X);
            }
        }

        public override byte[] Step(byte[]? inputToken = null)
        {
            var res = GSSAPI.InitSecContext(_credential, _context, _targetSpn, _mech, _flags, 0, _bindingData,
                inputToken);
            _context = res.Context;

            if (!res.MoreNeeded)
            {
                Complete = true;
                IntegrityAvailable = (res.Flags & GssapiContextFlags.GSS_C_INTEG_FLAG) != 0;
                ConfidentialityAvailable = (res.Flags & GssapiContextFlags.GSS_C_CONF_FLAG) != 0;
            }

            return res.OutputToken ?? Array.Empty<byte>();
        }

        public override byte[] Wrap(ReadOnlySpan<byte> data, bool encrypt)
        {
            if (_context == null || !Complete)
                throw new InvalidOperationException("Cannot wrap without a completed context");

            (byte[] wrappedData, bool _) = GSSAPI.Wrap(_context, encrypt, 0, data);
            return wrappedData;
        }

        public override byte[] Unwrap(ReadOnlySpan<byte> data)
        {
            if (_context == null || !Complete)
                throw new InvalidOperationException("Cannot unwrap without a completed context");

            (byte[] unwrappedData, bool _1, int _2) = GSSAPI.Unwrap(_context, data);
            return unwrappedData;
        }

        public override uint MaxWrapSize(uint outputSize, bool confReq)
        {
            if (_context == null || !Complete)
                throw new InvalidOperationException("Cannot get max wrap size without a completed context");

            return GSSAPI.WrapSizeLimit(_context, confReq, 0, outputSize);
        }

        public override void Dispose()
        {
            _credential?.Dispose();
            _context?.Dispose();
            _targetSpn?.Dispose();
        }
    }

    internal class SspiContext : SecurityContext
    {
        private readonly SspiCredential _credential;
        private readonly ChannelBindings? _bindingData;
        private readonly string _targetSpn;
        private readonly InitiatorContextRequestFlags _flags = InitiatorContextRequestFlags.ISC_REQ_MUTUAL_AUTH |
            InitiatorContextRequestFlags.ISC_REQ_SEQUENCE_DETECT;
        private SspiSecContext? _context;
        private UInt32 _blockSize = 0;
        private UInt32 _trailerSize = 0;

        public SspiContext(string? username, string? password, AuthenticationMethod method, string target,
            ChannelBindings? channelBindings, bool integrity, bool confidentiality)
        {
            _bindingData = channelBindings;
            _targetSpn = target;

            string package = method == AuthenticationMethod.Kerberos ? "Kerberos" : "Negotiate";
            WinNTAuthIdentity? identity = null;
            if (!string.IsNullOrEmpty(username) || !string.IsNullOrEmpty(password))
            {
                string? domain = null;
                if (username?.Contains('\\') == true)
                {
                    string[] stringSplit = username.Split('\\', 2);
                    domain = stringSplit[0];
                    username = stringSplit[1];
                }

                identity = new WinNTAuthIdentity(username, domain, password);
            }
            _credential = SSPI.AcquireCredentialsHandle(null, package, CredentialUse.SECPKG_CRED_OUTBOUND,
                identity);

            if (integrity)
                _flags |= InitiatorContextRequestFlags.ISC_REQ_INTEGRITY;

            if (confidentiality)
                _flags |= InitiatorContextRequestFlags.ISC_REQ_INTEGRITY |
                    InitiatorContextRequestFlags.ISC_REQ_CONFIDENTIALITY;

        }

        public override byte[] Step(byte[]? inputToken = null)
        {
            int bufferCount = 0;
            if (inputToken != null)
                bufferCount++;

            if (_bindingData != null)
                bufferCount++;

            unsafe
            {
                fixed (byte * input = inputToken)
                {
                    Span<Helpers.SecBuffer> inputBuffers = stackalloc Helpers.SecBuffer[bufferCount];

                    if (inputToken != null)
                    {
                        inputBuffers[0].cbBuffer = (UInt32)inputToken.Length;
                        inputBuffers[0].BufferType = (UInt32)SecBufferType.SECBUFFER_TOKEN;
                        inputBuffers[0].pvBuffer = (IntPtr)input;
                    }

                    if (_bindingData != null)
                    {
                        throw new NotImplementedException();
                    }

                    _context = SSPI.InitializeSecurityContext(_credential, _context, _targetSpn, _flags,
                        TargetDataRep.SECURITY_NATIVE_DREP, inputBuffers, new[] { SecBufferType.SECBUFFER_TOKEN, });

                    if (!_context.MoreNeeded)
                    {
                        Complete = true;
                        IntegrityAvailable =
                            (_context.Flags & InitiatorContextReturnFlags.ISC_RET_INTEGRITY) != 0;
                        ConfidentialityAvailable =
                            (_context.Flags & InitiatorContextReturnFlags.ISC_RET_CONFIDENTIALITY) != 0;

                        Span<Helpers.SecPkgContext_Sizes> sizes = stackalloc Helpers.SecPkgContext_Sizes[1];
                        fixed (Helpers.SecPkgContext_Sizes* sizesPtr = sizes)
                        {
                            SSPI.QueryContextAttributes(_context, SecPkgAttribute.SECPKG_ATTR_SIZES,
                                (IntPtr)sizesPtr);

                            _trailerSize = sizes[0].cbSecurityTrailer;
                            _blockSize = sizes[0].cbBlockSize;
                        }
                    }

                    return _context.OutputBuffers.Length > 0 ? _context.OutputBuffers[0] : Array.Empty<byte>();
                }
            }

            throw new NotImplementedException("step");
        }

        public override byte[] Wrap(ReadOnlySpan<byte> data, bool encrypt)
        {
            if (_context == null || !Complete)
                throw new InvalidOperationException("Cannot wrap without a completed context");

            unsafe
            {
                ArrayPool<byte> shared = ArrayPool<byte>.Shared;
                byte[] token = shared.Rent((int)_trailerSize);
                byte[] padding = shared.Rent((int)_blockSize);

                try
                {
                    fixed (byte* tokenPtr = token, dataPtr = data, paddingPtr = padding)
                    {
                        Span<Helpers.SecBuffer> buffers = stackalloc Helpers.SecBuffer[3];
                        buffers[0].BufferType = (UInt32)SecBufferType.SECBUFFER_TOKEN;
                        buffers[0].cbBuffer = _trailerSize;
                        buffers[0].pvBuffer = (IntPtr)tokenPtr;

                        buffers[1].BufferType = (UInt32)SecBufferType.SECBUFFER_DATA;
                        buffers[1].cbBuffer = (UInt32)data.Length;
                        buffers[1].pvBuffer = (IntPtr)dataPtr;

                        buffers[2].BufferType = (UInt32)SecBufferType.SECBUFFER_PADDING;
                        buffers[2].cbBuffer = _blockSize;
                        buffers[2].pvBuffer = (IntPtr)paddingPtr;

                        SSPI.EncryptMessage(_context, 0, buffers, 0);

                        byte[] wrapped = new byte[buffers[0].cbBuffer + buffers[1].cbBuffer + buffers[2].cbBuffer];
                        int offset = 0;
                        if (buffers[0].cbBuffer > 0)
                        {
                            Buffer.BlockCopy(token, 0, wrapped, offset, (int)buffers[0].cbBuffer);
                            offset += (int)buffers[0].cbBuffer;
                        }

                        Marshal.Copy((IntPtr)dataPtr, wrapped, offset, (int)buffers[1].cbBuffer);
                        offset += (int)buffers[1].cbBuffer;

                        if (buffers[2].cbBuffer > 0)
                        {
                            Buffer.BlockCopy(padding, 0, wrapped, offset, (int)buffers[2].cbBuffer);
                            offset += (int)buffers[2].cbBuffer;
                        }

                        return wrapped;
                    }
                }
                finally
                {
                    shared.Return(token);
                    shared.Return(padding);
                }
            }
        }

        public override byte[] Unwrap(ReadOnlySpan<byte> data)
        {
            if (_context == null || !Complete)
                throw new InvalidOperationException("Cannot wrap without a completed context");

            unsafe
            {
                fixed (byte* dataPtr = data)
                {
                    Span<Helpers.SecBuffer> buffers = stackalloc Helpers.SecBuffer[2];
                    buffers[0].BufferType = (UInt32)SecBufferType.SECBUFFER_STREAM;
                    buffers[0].cbBuffer = (UInt32)data.Length;
                    buffers[0].pvBuffer = (IntPtr)dataPtr;

                    buffers[1].BufferType = (UInt32)SecBufferType.SECBUFFER_DATA;
                    buffers[1].cbBuffer = 0;
                    buffers[1].pvBuffer = IntPtr.Zero;

                    SSPI.DecryptMessage(_context, buffers, 0);

                    byte[] unwrapped = new byte[buffers[1].cbBuffer];
                    Marshal.Copy(buffers[1].pvBuffer, unwrapped, 0, unwrapped.Length);

                    return unwrapped;
                }
            }
        }

        public override UInt32 MaxWrapSize(UInt32 outputSize, bool confReq)
        {
            if (_context == null || !Complete)
                throw new InvalidOperationException("Cannot wrap without a completed context");

            throw new NotImplementedException();
        }

        public override void Dispose()
        {
            _credential.Dispose();
            _context?.Dispose();
        }
    }
}

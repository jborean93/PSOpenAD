using PSOpenAD.Native;
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

namespace PSOpenAD
{
    public enum AuthenticationMethod
    {
        Default,
        Anonymous,
        Simple,
        Negotiate,
        Kerberos,
    }

    public sealed class AuthenticationProvider
    {
        public AuthenticationMethod Method { get; }
        public string NativeId { get; }
        public bool Available { get; }
        public bool CanSign { get; }
        public bool SupportsCB { get; }
        public string Details { get; }

        public AuthenticationProvider(AuthenticationMethod method, string nativeId, bool available, bool canSign,
            bool supportsCB, string details)
        {
            Method = method;
            NativeId = nativeId;
            Available = available;
            CanSign = canSign;
            SupportsCB = supportsCB;
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

    internal abstract class SecurityContext : IDisposable
    {
        public bool Complete { get; internal set; }
        public bool IntegrityAvailable { get; internal set; }
        public bool ConfidentialityAvailable { get; internal set; }

        public abstract byte[] Step(byte[]? inputToken = null);
        public abstract byte[] Wrap(byte[] data, bool encrypt);
        public abstract byte[] Unwrap(byte[] data);

        public abstract UInt32 MaxWrapSize(UInt32 outputSize, bool confReq);

        public abstract void Dispose();
        ~SecurityContext() => Dispose();
    }

    internal class GssapiContext : SecurityContext
    {
        private readonly SafeGssapiCred _credential;
        private readonly SafeGssapiName _targetSpn;
        private readonly byte[] _mech;
        private readonly SafeMemoryBuffer? _bindingData;
        private readonly GssapiContextFlags _flags = GssapiContextFlags.GSS_C_MUTUAL_FLAG |
            GssapiContextFlags.GSS_C_SEQUENCE_FLAG;
        private SafeGssapiSecContext? _context;
        private Helpers.gss_channel_bindings_struct? _bindings;

        public GssapiContext(string? username, string? password, AuthenticationMethod method, string target,
            byte[]? channelBindings, bool integrity, bool confidentiality)
        {
            _mech = method == AuthenticationMethod.Negotiate ? GSSAPI.SPNEGO : GSSAPI.KERBEROS;
            _targetSpn = GSSAPI.ImportName(target, GSSAPI.GSS_C_NT_HOSTBASED_SERVICE);

            List<byte[]> mechList = new List<byte[]>() { _mech };
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
                // Kerberos always sets INTEG | CONF unless this flag is set. When operating over TLS Windows will
                // reject any auth with these flags so this needs to be set to disable that behaviour.
                GSSAPI.SetCredOption(_credential, GSSAPI.GSS_KRB5_CRED_NO_CI_FLAGS_X);
            }

            if (channelBindings != null)
            {
                _bindingData = new SafeMemoryBuffer(channelBindings.Length);
                Marshal.Copy(channelBindings, 0, _bindingData.DangerousGetHandle(), channelBindings.Length);

                _bindings = new Helpers.gss_channel_bindings_struct()
                {
                    application_data = new Helpers.gss_buffer_desc()
                    {
                        length = new IntPtr(channelBindings.Length),
                        value = _bindingData.DangerousGetHandle(),
                    },
                };
            }
        }

        public override byte[] Step(byte[]? inputToken = null)
        {
            var res = GSSAPI.InitSetContext(_credential, _context, _targetSpn, _mech, _flags, 0, _bindings,
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

        public override byte[] Wrap(byte[] data, bool encrypt)
        {
            if (_context == null || !Complete)
                throw new InvalidOperationException("Cannot wrap without a completed context");

            (byte[] wrappedData, bool _) = GSSAPI.Wrap(_context, encrypt, 0, data);
            return wrappedData;
        }

        public override byte[] Unwrap(byte[] data)
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
            _credential.Dispose();
            _context?.Dispose();
            _targetSpn?.Dispose();
            _bindingData?.Dispose();
        }
    }
}

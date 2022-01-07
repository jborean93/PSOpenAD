using PSOpenAD.Native;
using System;
using System.Collections.Generic;

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
        private readonly SafeGssapiCred _credential;
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
            _credential.Dispose();
            _context?.Dispose();
            _targetSpn?.Dispose();
        }
    }
}

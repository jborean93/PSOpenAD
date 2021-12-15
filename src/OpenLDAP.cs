using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace PSOpenAD
{
    internal static partial class Helpers
    {
        [StructLayout(LayoutKind.Sequential)]
        public struct berval
        {
            public int bv_len;
            public IntPtr bv_val;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct ldapcontrol
        {
            public IntPtr ldctl_oid;
            public berval ldctl_value;
            [MarshalAs(UnmanagedType.U1)] public bool ldctl_iscritical;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct timeval
        {
            public int tv_sec;
            public int tv_usec;
        }
    }

    internal static class OpenLDAP
    {
        //private const string LIB_LDAP = "libldap.so";
        private const string LIB_LDAP = "/opt/openldap-2.6.0/lib/libldap.so";

        public delegate int LDAP_SASL_INTERACT_PROC(
            IntPtr ld,
            int flags,
            IntPtr defaults,
            IntPtr interact);

        [DllImport(LIB_LDAP)]
        public static extern int ldap_abandon_ext(
            SafeHandle ld,
            int msgid,
            IntPtr sctrls,
            IntPtr cctrls);

        [DllImport(LIB_LDAP)]
        public static extern int ldap_count_messages(
            SafeHandle ld,
            IntPtr result);

        [DllImport(LIB_LDAP)]
        public static extern void ldap_controls_free(
            IntPtr ctrls);

        [DllImport(LIB_LDAP)]
        public static extern IntPtr ldap_err2string(
            int error);

        [DllImport(LIB_LDAP)]
        public static extern int ldap_get_option(
            SafeHandle ld,
            LDAPOption option,
            out IntPtr outvalue);

        [DllImport(LIB_LDAP)]
        public static extern int ldap_get_option(
            SafeHandle ld,
            LDAPOption option,
            out int outvalue);

        [DllImport(LIB_LDAP)]
        public static extern int ldap_get_option(
            SafeHandle ld,
            LDAPOption option,
            out SafeLdapMemory outvalue);

        [DllImport(LIB_LDAP)]
        public static extern int ldap_initialize(
            out SafeLdapHandle ldp,
            string uri);

        [DllImport(LIB_LDAP)]
        public static extern void ldap_memfree(
            IntPtr p);

        [DllImport(LIB_LDAP)]
        public static extern void ldap_memvfree(
            IntPtr p);

        [DllImport(LIB_LDAP)]
        public static extern int ldap_msgfree(
            IntPtr msg);

        [DllImport(LIB_LDAP)]
        public static extern int ldap_msgtype(
            SafeHandle msg);

        [DllImport(LIB_LDAP)]
        public static extern int ldap_msgid(
            SafeHandle msg);

        [DllImport(LIB_LDAP)]
        public static extern int ldap_parse_result(
            SafeHandle ld,
            IntPtr result,
            out int errcodep,
            out SafeLdapMemory matcheddnp,
            out SafeLdapMemory errmsgp,
            out SafeLdapMemoryArray referralsp,
            out SafeLdapControls serverctrlsp,
            int freeid);

        [DllImport(LIB_LDAP)]
        public static extern int ldap_parse_sasl_bind_result(
            SafeHandle ld,
            IntPtr result,
            ref Helpers.berval servercredp,
            int freeit);

        [DllImport(LIB_LDAP)]
        public static extern int ldap_result(
            SafeHandle ld,
            int msgid,
            LDAPMessageAll all,
            ref Helpers.timeval timeout,
            out SafeLdapMessage result);

        [DllImport(LIB_LDAP)]
        public static extern int ldap_result2error(
            SafeHandle ld,
            IntPtr res,
            int freeit);

        [DllImport(LIB_LDAP)]
        public static extern int ldap_sasl_bind(
            SafeHandle ld,
            string dn,
            string? mechanism,
            IntPtr cred,
            IntPtr sctrls,
            IntPtr cctrls,
            ref int msgidp);

        [DllImport(LIB_LDAP)]
        public static extern int ldap_sasl_interactive_bind(
            SafeHandle ld,
            string dn,
            string mechs,
            IntPtr sctrls,
            IntPtr cctrls,
            SASLInteractionFlags flags,
            [MarshalAs(UnmanagedType.FunctionPtr)] LDAP_SASL_INTERACT_PROC interact,
            IntPtr defaults,
            IntPtr result,
            out IntPtr rmechp,
            out int msgidp);

        [DllImport(LIB_LDAP)]
        public static extern int ldap_set_option(
            SafeHandle ld,
            LDAPOption option,
            [In] ref int invalue);

        [DllImport(LIB_LDAP)]
        public static extern int ldap_set_option(
            SafeHandle ld,
            LDAPOption option,
            IntPtr invalue);

        [DllImport(LIB_LDAP)]
        public static extern int ldap_simple_bind(
            SafeHandle ld,
            string who,
            string passwd);

        [DllImport(LIB_LDAP)]
        public static extern int ldap_simple_bind_s(
            SafeHandle ld,
            string who,
            string passwd);

        [DllImport(LIB_LDAP)]
        public static extern int ldap_start_tls_s(
            SafeLdapHandle ld,
            IntPtr serverctrls,
            IntPtr clientctrls);

        [DllImport(LIB_LDAP)]
        public static extern int ldap_unbind(
            IntPtr ld);

        public static string Err2String(int error)
        {
            return Marshal.PtrToStringUTF8(ldap_err2string(error)) ?? "";
        }

        public static SafeLdapHandle Initialize(string uri)
        {
            int err = ldap_initialize(out var ldap, uri);
            if (err != 0)
                throw new LDAPException(null, err, "ldap_initialize");

            return ldap;
        }

        public static Task SaslInteractiveBindAsync(SafeLdapHandle ldap, string dn, string mech, SaslInteract prompt,
            int timeoutMS = 5000, CancellationToken? cancelToken = null)
        {
            return Task.Run(() =>
            {
                int res = 0;
                do
                {
                    SafeLdapMessage result = new SafeLdapMessage();
                    res = ldap_sasl_interactive_bind(ldap, dn, mech, IntPtr.Zero, IntPtr.Zero,
                        SASLInteractionFlags.LDAP_SASL_QUIET, prompt.SaslInteractProc, IntPtr.Zero,
                        result.DangerousGetHandle(), out var rmech, out var msgid);
                    result.Dispose();

                    if (res != (int)LDAPResultCode.LDAP_SASL_BIND_IN_PROGRESS)
                        break;

                    do
                    {
                        Helpers.timeval timeout = new Helpers.timeval()
                        {
                            tv_sec = (int)Math.Floor((double)timeoutMS / 1000),
                            tv_usec = timeoutMS % 1000,
                        };
                        res = ldap_result(ldap, msgid, LDAPMessageAll.LDAP_MSG_ALL, ref timeout, out result);
                        if (res == 0)
                        {
                            timeoutMS -= 200;
                        }
                        else if (res == -1)
                        {
                            res = GetOptionInt(ldap, LDAPOption.LDAP_OPT_RESULT_CODE);
                            throw new LDAPException(ldap, res, "ldap_result");
                        }
                        else
                        {
                            break;
                        }

                        if (cancelToken?.IsCancellationRequested == true)
                            throw new TaskCanceledException();
                    }
                    while (timeoutMS > 0);

                    if (res == 0)
                        throw new TimeoutException();

                    ldap_parse_result(ldap, result.DangerousGetHandle(), out res, out var _1,
                        out var errMsg, out var _2, out var _3, 0);
                    if (res != 0 && res != (int)LDAPResultCode.LDAP_SASL_BIND_IN_PROGRESS)
                    {
                        string msg = Marshal.PtrToStringUTF8(errMsg.DangerousGetHandle()) ?? "";
                        throw new LDAPException(ldap, res, "ldap_sasl_interactive_bind", errorMessage: msg);
                    }
                }
                while (res == (int)LDAPResultCode.LDAP_SASL_BIND_IN_PROGRESS);

                if (res != 0)
                    throw new LDAPException(ldap, res, "ldap_sasl_interactive_bind");
            });
        }

        // FIXME: Set saner timeoutMS value and handle a timeout of -1 (use global default)
        public static Task SimpleBindAsync(SafeLdapHandle ldap, string who, string password,
            int timeoutMS = 5000, CancellationToken? cancelToken = null)
        {
            int msgid = 0;
            int res;
            using (SafeMemoryBuffer pass = new SafeMemoryBuffer(password))
            {
                Helpers.berval cred = new Helpers.berval()
                {
                    bv_len = pass.Length,
                    bv_val = pass.DangerousGetHandle(),
                };

                using SafeMemoryBuffer credPtr = new SafeMemoryBuffer(Marshal.SizeOf(cred));
                Marshal.StructureToPtr(cred, credPtr.DangerousGetHandle(), false);
                res = ldap_sasl_bind(ldap, who, null, credPtr.DangerousGetHandle(), IntPtr.Zero, IntPtr.Zero,
                    ref msgid);
            }

            if (res != 0)
                throw new LDAPException(ldap, res, "ldap_sasl_bind");

            return Task.Run(() =>
            {
                SafeLdapMessage result;
                int res = 0;

                // This is ugly but ldap_abandon_ext doesn't seem to cancel the ldap_result, instead check every
                // 200 milliseconds that the caller hasn't cancelled the request (pressed ctrl+c) and cancel if so.
                do
                {
                    Helpers.timeval timeout = new Helpers.timeval()
                    {
                        tv_sec = (int)Math.Floor((double)timeoutMS / 1000),
                        tv_usec = timeoutMS % 1000,
                    };
                    res = ldap_result(ldap, msgid, LDAPMessageAll.LDAP_MSG_ALL, ref timeout, out result);
                    if (res == 0)
                    {
                        timeoutMS -= 200;
                    }
                    else if (res == -1)
                    {
                        res = GetOptionInt(ldap, LDAPOption.LDAP_OPT_RESULT_CODE);
                        throw new LDAPException(ldap, res, "ldap_result");
                    }
                    else
                    {
                        break;
                    }

                    if (cancelToken?.IsCancellationRequested == true)
                        throw new TaskCanceledException();
                }
                while (timeoutMS > 0);

                if (res == 0)
                    throw new TimeoutException();

                ldap_parse_result(ldap, result.DangerousGetHandle(), out var errorCode, out var _1,
                    out var errMsg, out var _2, out var _3, 0);
                if (errorCode != 0)
                {
                    string msg = Marshal.PtrToStringUTF8(errMsg.DangerousGetHandle()) ?? "";
                    throw new LDAPException(ldap, errorCode, "ldap_sasl_bind", errorMessage: msg);
                }
            });
        }

        public static void StartTlsS(SafeLdapHandle ldap)
        {
            int res = ldap_start_tls_s(ldap, IntPtr.Zero, IntPtr.Zero);
            if (res != 0)
                throw new LDAPException(ldap, res, "ldap_start_tls_ts");
        }

        public static int CountMessages(SafeLdapHandle ldap, SafeHandle result)
        {
            return ldap_count_messages(ldap, result.DangerousGetHandle());
        }

        public static int GetOptionInt(SafeLdapHandle ldap, LDAPOption option)
        {
            int res = ldap_get_option(ldap, option, out int value);
            if (res != 0)
                throw new LDAPException(ldap, res, $"ldap_get_option({option})");

            return value;
        }

        public static string GetOptionString(SafeLdapHandle ldap, LDAPOption option)
        {
            int res = ldap_get_option(ldap, option, out SafeLdapMemory value);
            if (res != 0)
                throw new LDAPException(ldap, res, $"ldap_get_option({option})");

            return Marshal.PtrToStringUTF8(value.DangerousGetHandle()) ?? "";
        }

        public static List<string> GetOptionSaslMechList(SafeLdapHandle ldap)
        {
            LDAPOption option = LDAPOption.LDAP_OPT_X_SASL_MECHLIST;
            int res = ldap_get_option(ldap, option, out IntPtr value);
            if (res != 0)
                throw new LDAPException(ldap, res, $"ldap_get_option({option})");

            List<string> mechs = new List<string>(); ;
            while (true)
            {
                string? mech = Marshal.PtrToStringUTF8(Marshal.ReadIntPtr(value));
                if (String.IsNullOrEmpty(mech))
                    break;

                mechs.Add(mech);
                value = IntPtr.Add(value, IntPtr.Size);
            }

            return mechs;
        }

        public static void SetOption(SafeLdapHandle ldap, LDAPOption option, int value)
        {
            int res = ldap_set_option(ldap, option, ref value);
            if (res != 0)
                throw new LDAPException(ldap, res, $"ldap_set_option({option})");
        }

        public static void SetOption(SafeLdapHandle ldap, LDAPOption option, IntPtr value)
        {
            int res = ldap_set_option(ldap, option, value);
            if (res != 0)
                throw new LDAPException(ldap, res, $"ldap_set_option({option})");
        }
    }

    public class LDAPException : Exception
    {
        public int ErrorCode { get; }

        public string? ErrorMessage { get; }

        internal LDAPException(SafeLdapHandle? ldap, int error)
            : base(GetExceptionMessage(ldap, error, null, null)) => ErrorCode = error;

        internal LDAPException(SafeLdapHandle? ldap, int error, string method, string? errorMessage = null)
            : base(GetExceptionMessage(ldap, error, method, errorMessage))
        {
            ErrorCode = error;
            ErrorMessage = errorMessage;
        }

        private static string GetExceptionMessage(SafeLdapHandle? ldap, int error, string? method,
             string? errorMessage)
        {
            method = String.IsNullOrWhiteSpace(method) ? "LDAP Call" : method;
            string errString = OpenLDAP.Err2String(error);
            if (String.IsNullOrWhiteSpace(errorMessage) && ldap?.IsInvalid == false && ldap?.IsClosed == false)
                errorMessage = OpenLDAP.GetOptionString(ldap, LDAPOption.LDAP_OPT_DIAGNOSTIC_MESSAGE);

            string msg = $"{method} failed ({error} - {errString})";
            if (!String.IsNullOrWhiteSpace(errorMessage))
                msg += $" - {errorMessage}";

            return msg;
        }
    }

    internal class SafeLdapHandle : SafeHandle
    {
        internal SafeLdapHandle() : base(IntPtr.Zero, true) { }

        public override bool IsInvalid => handle == IntPtr.Zero;

        protected override bool ReleaseHandle()
        {
            return OpenLDAP.ldap_unbind(handle) == 0;
        }
    }

    internal class SafeLdapMessage : SafeHandle
    {
        internal SafeLdapMessage() : base(IntPtr.Zero, true) { }

        public override bool IsInvalid => handle == IntPtr.Zero;

        protected override bool ReleaseHandle()
        {
            return OpenLDAP.ldap_msgfree(handle) == 0;
        }
    }

    internal class SafeLdapMemory : SafeHandle
    {
        internal SafeLdapMemory() : base(IntPtr.Zero, true) { }

        public override bool IsInvalid => handle == IntPtr.Zero;

        protected override bool ReleaseHandle()
        {
            OpenLDAP.ldap_memfree(handle);
            return true;
        }
    }

    internal class SafeLdapMemoryArray : SafeHandle
    {
        internal SafeLdapMemoryArray() : base(IntPtr.Zero, true) { }

        public override bool IsInvalid => handle == IntPtr.Zero;

        protected override bool ReleaseHandle()
        {
            OpenLDAP.ldap_memvfree(handle);
            return true;
        }
    }

    internal class SafeLdapControls : SafeHandle
    {
        internal SafeLdapControls() : base(IntPtr.Zero, true) { }

        public override bool IsInvalid => handle == IntPtr.Zero;

        protected override bool ReleaseHandle()
        {
            OpenLDAP.ldap_controls_free(handle);
            return true;
        }
    }

    internal class SafeMemoryBuffer : SafeHandle
    {
        public int Length { get; } = 0;

        internal SafeMemoryBuffer() : base(IntPtr.Zero, true) { }

        internal SafeMemoryBuffer(int size) : base(Marshal.AllocHGlobal(size), true) => Length = size;

        internal SafeMemoryBuffer(string value) : base(IntPtr.Zero, true)
        {
            byte[] data = Encoding.UTF8.GetBytes(value);
            Length = data.Length;

            handle = Marshal.AllocHGlobal(Length);
            Marshal.Copy(data, 0, handle, Length);
        }

        internal SafeMemoryBuffer(IntPtr buffer, bool ownsHandle) : base(buffer, ownsHandle) { }

        public override bool IsInvalid => handle == IntPtr.Zero;

        protected override bool ReleaseHandle()
        {
            Marshal.FreeHGlobal(handle);
            return true;
        }
    }

    internal enum LDAPChannelBinding
    {
        LDAP_OPT_X_SASL_CBINDING_NONE = 0,
        LDAP_OPT_X_SASL_CBINDING_TLS_UNIQUE = 1,
        LDAP_OPT_X_SASL_CBINDING_TLS_ENDPOINT = 2,
    }

    internal enum LDAPResultType
    {
        LDAP_RES_BIND = 0x61,
        LDAP_RES_SEARCH_ENTRY = 0x64,
        LDAP_RES_SEARCH_REFERENCE = 0x73,
        LDAP_RES_SEARCH_RESULT = 0x65,
        LDAP_RES_MODIFY = 0x67,
        LDAP_RES_ADD = 0x69,
        LDAP_RES_DELETE = 0x6b,
        LDAP_RES_MODDN = 0x6d,
        LDAP_RES_COMPARE = 0x6f,
        LDAP_RES_EXTENDED = 0x78,
        LDAP_RES_INTERMEDIATE = 0x79,
    }

    public enum LDAPResultCode
    {
        LDAP_SASL_BIND_IN_PROGRESS = 14,
    }

    internal enum LDAPMessageAll
    {
        LDAP_MSG_ONE = 0x00,
        LDAP_MSG_ALL = 0x01,
        LDAP_MSG_RECEIVED = 0x02,
    }

    internal enum LDAPOption
    {
        LDAP_OPT_API_INFO = 0x0000,
        LDAP_OPT_DESC = 0x0001,
        LDAP_OPT_DEREF = 0x0002,
        LDAP_OPT_SIZELIMIT = 0x0003,
        LDAP_OPT_TIMELIMIT = 0x0004,
        LDAP_OPT_REFERRALS = 0x0008,
        LDAP_OPT_RESTART = 0x0009,
        LDAP_OPT_PROTOCOL_VERSION = 0x0011,
        LDAP_OPT_SERVER_CONTROLS = 0x0012,
        LDAP_OPT_CLIENT_CONTROLS = 0x0013,
        LDAP_OPT_API_FEATURE_INFO = 0x0015,
        LDAP_OPT_HOST_NAME = 0x0030,
        LDAP_OPT_RESULT_CODE = 0x0031,
        LDAP_OPT_ERROR_NUMBER = LDAP_OPT_RESULT_CODE,
        LDAP_OPT_DIAGNOSTIC_MESSAGE = 0x0032,
        LDAP_OPT_ERROR_STRING = LDAP_OPT_DIAGNOSTIC_MESSAGE,
        LDAP_OPT_MATCHED_DN = 0x0033,
        LDAP_OPT_SSPI_FLAGS = 0x0092,
        LDAP_OPT_SIGN = 0x0095,
        LDAP_OPT_ENCRYPT = 0x0096,
        LDAP_OPT_SASL_METHOD = 0x0097,
        LDAP_OPT_SECURITY_CONTEXT = 0x0099,
        LDAP_OPT_API_EXTENSION_BASE = 0x4000,
        LDAP_OPT_DEBUG_LEVEL = 0x5001,
        LDAP_OPT_TIMEOUT = 0x5002,
        LDAP_OPT_REFHOPLIMIT = 0x5003,
        LDAP_OPT_NETWORK_TIMEOUT = 0x5005,
        LDAP_OPT_URI = 0x5006,
        LDAP_OPT_REFERRAL_URLS = 0x5007,
        LDAP_OPT_SOCKBUF = 0x5008,
        LDAP_OPT_DEFBASE = 0x5009,
        LDAP_OPT_CONNECT_ASYNC = 0x5010,
        LDAP_OPT_CONNECT_CB = 0x5011,
        LDAP_OPT_SESSION_REFCNT = 0x5012,
        LDAP_OPT_KEEPCONN = 0x5013,
        LDAP_OPT_X_TLS = 0x6000,
        LDAP_OPT_X_TLS_CTX = 0x6001,
        LDAP_OPT_X_TLS_CACERTFILE = 0x6002,
        LDAP_OPT_X_TLS_CACERTDIR = 0x6003,
        LDAP_OPT_X_TLS_CERTFILE = 0x6004,
        LDAP_OPT_X_TLS_KEYFILE = 0x6005,
        LDAP_OPT_X_TLS_REQUIRE_CERT = 0x6006,
        LDAP_OPT_X_TLS_PROTOCOL_MIN = 0x6007,
        LDAP_OPT_X_TLS_CIPHER_SUITE = 0x6008,
        LDAP_OPT_X_TLS_RANDOM_FILE = 0x6009,
        LDAP_OPT_X_TLS_SSL_CTX = 0x600a,
        LDAP_OPT_X_TLS_CRLCHECK = 0x600b,
        LDAP_OPT_X_TLS_CONNECT_CB = 0x600c,
        LDAP_OPT_X_TLS_CONNECT_ARG = 0x600d,
        LDAP_OPT_X_TLS_DHFILE = 0x600e,
        LDAP_OPT_X_TLS_NEWCTX = 0x600f,
        LDAP_OPT_X_TLS_CRLFILE = 0x6010,
        LDAP_OPT_X_TLS_PACKAGE = 0x6011,
        LDAP_OPT_X_TLS_ECNAME = 0x6012,
        LDAP_OPT_X_TLS_VERSION = 0x6013,
        LDAP_OPT_X_TLS_CIPHER = 0x6014,
        LDAP_OPT_X_TLS_PEERCERT = 0x6015,
        LDAP_OPT_X_TLS_CACERT = 0x6016,
        LDAP_OPT_X_TLS_CERT = 0x6017,
        LDAP_OPT_X_TLS_KEY = 0x6018,
        LDAP_OPT_X_TLS_PEERKEY_HASH = 0x6019,
        LDAP_OPT_X_TLS_REQUIRE_SAN = 0x601a,
        LDAP_OPT_X_SASL_MECH = 0x6100,
        LDAP_OPT_X_SASL_REALM = 0x6101,
        LDAP_OPT_X_SASL_AUTHCID = 0x6102,
        LDAP_OPT_X_SASL_AUTHZID = 0x6103,
        LDAP_OPT_X_SASL_SSF = 0x6104,
        LDAP_OPT_X_SASL_SSF_EXTERNAL = 0x6105,
        LDAP_OPT_X_SASL_SECPROPS = 0x6106,
        LDAP_OPT_X_SASL_SSF_MIN = 0x6107,
        LDAP_OPT_X_SASL_SSF_MAX = 0x6108,
        LDAP_OPT_X_SASL_MAXBUFSIZE = 0x6109,
        LDAP_OPT_X_SASL_MECHLIST = 0x610a,
        LDAP_OPT_X_SASL_NOCANON = 0x610b,
        LDAP_OPT_X_SASL_USERNAME = 0x610c,
        LDAP_OPT_X_SASL_GSS_CREDS = 0x610d,
        LDAP_OPT_X_SASL_CBINDING = 0x610e,
        LDAP_OPT_X_KEEPALIVE_IDLE = 0x6300,
        LDAP_OPT_X_KEEPALIVE_PROBES = 0x6301,
        LDAP_OPT_X_KEEPALIVE_INTERVAL = 0x6302,
        LDAP_OPT_PRIVATE_EXTENSION_BASE = 0x7000,
    }

    public enum LDAPTlsSettings
    {
        LDAP_OPT_X_TLS_NEVER = 0,
        LDAP_OPT_X_TLS_HARD = 1,
        LDAP_OPT_X_TLS_DEMAND = 2,
        LDAP_OPT_X_TLS_ALLOW = 3,
        LDAP_OPT_X_TLS_TRY = 4,
    }

    public enum SASLInteractionFlags
    {
        LDAP_SASL_AUTOMATIC = 0,
        LDAP_SASL_INTERACTIVE = 1,
        LDAP_SASL_QUIET = 2
    }
}

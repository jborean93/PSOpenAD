using System;
using System.Runtime.InteropServices;

namespace PSOpenAD
{
    internal static partial class Helpers
    {
        [StructLayout(LayoutKind.Sequential)]
        public struct krb5_keyblock
        {
            public int magic;
            public int enctype;
            public int length;
            public IntPtr contexts;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct krb5_creds
        {
            public int magic;
            public IntPtr client;
            public IntPtr server;
            public krb5_keyblock keyblock;
            public krb5_ticket_times times;
            public int is_skey;
            public int ticket_flags;
            public IntPtr addresses;
            public krb5_data ticket;
            public krb5_data second_ticket;
            public IntPtr authdata;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct krb5_data
        {
            public int magic;
            public int length;
            public IntPtr data;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct krb5_ticket_times
        {
            public int authtime;
            public int starttime;
            public int endtime;
            public int renew_till;
        }
    }
    internal static class Kerberos
    {
        private const string KRB5_LIB = "libkrb5.so";

        [DllImport(KRB5_LIB)]
        public static extern int krb5_cc_close(
            SafeKrb5Context context,
            IntPtr cache);

        [DllImport(KRB5_LIB)]
        public static extern IntPtr krb5_cc_get_name(
            SafeKrb5Context context,
            SafeKrb5Ccache cache);

        [DllImport(KRB5_LIB)]
        public static extern IntPtr krb5_cc_get_type(
            SafeKrb5Context context,
            SafeKrb5Ccache cache);

        [DllImport(KRB5_LIB)]
        public static extern int krb5_cc_initialize(
            SafeKrb5Context context,
            SafeKrb5Ccache cache,
            SafeKrb5Principal principal);

        [DllImport(KRB5_LIB)]
        public static extern int krb5_cc_new_unique(
            SafeKrb5Context context,
            string type,
            string? hint,
            out SafeKrb5Ccache id);

        [DllImport(KRB5_LIB)]
        public static extern int krb5_cc_store_cred(
            SafeKrb5Context context,
            SafeKrb5Ccache cache,
            SafeKrb5Creds creds);

        [DllImport(KRB5_LIB)]
        public static extern void krb5_free_context(
            IntPtr context);

        [DllImport(KRB5_LIB)]
        public static extern void krb5_free_cred_contents(
            SafeKrb5Context context,
            IntPtr val);

        [DllImport(KRB5_LIB)]
        public static extern void krb5_free_error_message(
            SafeKrb5Context ctx,
            IntPtr msg);

        [DllImport(KRB5_LIB)]
        public static extern SafeKrb5ErrorMessage krb5_get_error_message(
            SafeKrb5Context ctx,
            int code);

        [DllImport(KRB5_LIB)]
        public static extern int krb5_get_init_creds_opt_alloc(
            SafeKrb5Context context,
            out SafeKrb5GetInitCredsOpt opt);

        [DllImport(KRB5_LIB)]
        public static extern void krb5_get_init_creds_opt_free(
            SafeKrb5Context context,
            IntPtr opt);

        [DllImport(KRB5_LIB)] // For MIT
        public static extern int krb5_get_init_creds_opt_set_canonicalize(
            SafeKrb5GetInitCredsOpt opt,
            int canonicalize);

        [DllImport(KRB5_LIB)] // For Heimdal
        public static extern int krb5_get_init_creds_opt_set_canonicalize(
            SafeKrb5Context context,
            SafeKrb5GetInitCredsOpt opt,
            int canonicalize);

        [DllImport(KRB5_LIB)]
        public static extern int krb5_get_init_creds_password(
            SafeKrb5Context context,
            SafeKrb5Creds creds,
            SafeKrb5Principal client,
            string password,
            IntPtr prompter,
            IntPtr data,
            int start_time,
            IntPtr in_tkt_service,
            SafeKrb5GetInitCredsOpt k5_gic_options);

        [DllImport(KRB5_LIB)]
        public static extern int krb5_init_context(
            out SafeKrb5Context context);

        [DllImport(KRB5_LIB)]
        public static extern void krb5_free_principal(
            SafeKrb5Context context,
            IntPtr val);

        [DllImport(KRB5_LIB)]
        public static extern int krb5_parse_name_flags(
            SafeKrb5Context context,
            string name,
            PrincipalParseFlags flags,
            out SafeKrb5Principal principal_out);

        public static SafeKrb5Context InitContext()
        {
            krb5_init_context(out var ctx);
            return ctx;
        }

        public static string CCGetName(SafeKrb5Context context, SafeKrb5Ccache ccache)
        {
            return Marshal.PtrToStringUTF8(krb5_cc_get_name(context, ccache)) ?? "";
        }

        public static string CCGetType(SafeKrb5Context context, SafeKrb5Ccache ccache)
        {
            return Marshal.PtrToStringUTF8(krb5_cc_get_type(context, ccache)) ?? "";
        }

        public static void CCInitialize(SafeKrb5Context context, SafeKrb5Ccache ccache, SafeKrb5Principal principal)
        {
            int res = krb5_cc_initialize(context, ccache, principal);
            if (res != 0)
                throw new KerberosException(context, res, "krb5_cc_initialize");
        }

        public static SafeKrb5Ccache CCNewUnique(SafeKrb5Context context, string type, string? hint = null)
        {
            int res = krb5_cc_new_unique(context, type, hint, out var ccache);
            if (res != 0)
                throw new KerberosException(context, res, "krb5_cc_new_unique");

            ccache.Context = context;
            return ccache;
        }

        public static void CCStoreCred(SafeKrb5Context context, SafeKrb5Ccache ccache, SafeKrb5Creds creds)
        {
            int res = krb5_cc_store_cred(context, ccache, creds);
            if (res != 0)
                throw new KerberosException(context, res, "krb5_cc_store_cred");
        }

        public static SafeKrb5GetInitCredsOpt GetInitCredsOpt(SafeKrb5Context context)
        {
            int res = krb5_get_init_creds_opt_alloc(context, out var credsOpt);
            if (res != 0)
                throw new KerberosException(context, res, "krb5_get_init_creds_opt_alloc");

            credsOpt.Context = context;
            return credsOpt;
        }

        public static void GetInitCredsOptSetCanonicalize(SafeKrb5Context context, SafeKrb5GetInitCredsOpt credsOpt,
            bool canonicalize)
        {
            // FIXME: Pass in context for Heimdal (macOS).
            int res = krb5_get_init_creds_opt_set_canonicalize(credsOpt, canonicalize ? 1 : 0);
            if (res != 0)
                throw new KerberosException(context, res, "krb5_get_init_creds_opt_set_canonicalize");
        }

        public static SafeKrb5Creds GetInitCredsPassword(SafeKrb5Context context, SafeKrb5Principal client,
            SafeKrb5GetInitCredsOpt credsOpt, string password, int startTime = 0)
        {
            SafeKrb5Creds creds = new SafeKrb5Creds(context);
            int res = krb5_get_init_creds_password(context, creds, client, password, IntPtr.Zero, IntPtr.Zero,
                startTime, IntPtr.Zero, credsOpt);
            if (res != 0)
                throw new KerberosException(context, res, "krb5_get_init_creds_password");

            return creds;
        }

        public static SafeKrb5Principal ParseNameFlags(SafeKrb5Context context, string name, PrincipalParseFlags flags)
        {
            int res = krb5_parse_name_flags(context, name, flags, out var principal);
            if (res != 0)
                throw new KerberosException(context, res, "krb5_parse_name_flags");

            principal.Context = context;
            return principal;
        }
    }

    internal class SafeKrb5Ccache : SafeHandle
    {
        internal SafeKrb5Context Context = new SafeKrb5Context();

        internal SafeKrb5Ccache() : base(IntPtr.Zero, true) { }

        public override bool IsInvalid => handle == IntPtr.Zero;

        protected override bool ReleaseHandle()
        {
            return Kerberos.krb5_cc_close(Context, handle) == 0;
        }
    }

    internal class SafeKrb5Context : SafeHandle
    {
        internal SafeKrb5Context() : base(IntPtr.Zero, true) { }

        public override bool IsInvalid => handle == IntPtr.Zero;

        protected override bool ReleaseHandle()
        {
            Kerberos.krb5_free_context(handle);
            return true;
        }
    }

    internal class SafeKrb5Creds : SafeHandle
    {
        internal SafeKrb5Context Context = new SafeKrb5Context();

        internal SafeKrb5Creds(SafeKrb5Context context)
            : base(Marshal.AllocHGlobal(Marshal.SizeOf(typeof(Helpers.krb5_creds))), true) => Context = context;

        public override bool IsInvalid => handle == IntPtr.Zero;

        protected override bool ReleaseHandle()
        {
            Kerberos.krb5_free_cred_contents(Context, handle);
            Marshal.FreeHGlobal(handle);
            return true;
        }
    }

    internal class SafeKrb5GetInitCredsOpt : SafeHandle
    {
        internal SafeKrb5Context Context = new SafeKrb5Context();

        internal SafeKrb5GetInitCredsOpt() : base(IntPtr.Zero, true) { }

        public override bool IsInvalid => handle == IntPtr.Zero;

        protected override bool ReleaseHandle()
        {
            Kerberos.krb5_get_init_creds_opt_free(Context, handle);
            return true;
        }
    }

    internal class SafeKrb5ErrorMessage : SafeHandle
    {
        internal SafeKrb5Context Context = new SafeKrb5Context();

        internal SafeKrb5ErrorMessage() : base(IntPtr.Zero, true) { }

        public override bool IsInvalid => handle == IntPtr.Zero;

        public override string ToString()
        {
            return Marshal.PtrToStringUTF8(handle) ?? "";
        }

        protected override bool ReleaseHandle()
        {
            Kerberos.krb5_free_error_message(Context, handle);
            return true;
        }
    }

    internal class SafeKrb5Principal : SafeHandle
    {
        internal SafeKrb5Context Context = new SafeKrb5Context();

        internal SafeKrb5Principal() : base(IntPtr.Zero, true) { }

        public override bool IsInvalid => handle == IntPtr.Zero;

        protected override bool ReleaseHandle()
        {
            Kerberos.krb5_free_principal(Context, handle);
            return true;
        }
    }

    public class KerberosException : Exception
    {
        public int ErrorCode { get; }

        public string? ErrorMessage { get; }

        internal KerberosException(SafeKrb5Context context, int error)
            : base(GetExceptionMessage(context, error, null, null)) => ErrorCode = error;

        internal KerberosException(SafeKrb5Context context, int error, string method, string? errorMessage = null)
            : base(GetExceptionMessage(context, error, method, errorMessage))
        {
            ErrorCode = error;
            ErrorMessage = errorMessage;
        }

        private static string GetExceptionMessage(SafeKrb5Context context, int error, string? method, string? errorMessage)
        {
            method = String.IsNullOrWhiteSpace(method) ? "Kerberos Call" : method;
            using SafeKrb5ErrorMessage krb5Err = Kerberos.krb5_get_error_message(context, error);

            string msg = String.Format("{0} failed ({1}) - {2}", method, error, krb5Err.ToString());
            if (!String.IsNullOrWhiteSpace(errorMessage))
                msg += $" - {errorMessage}";

            return msg;
        }
    }

    [Flags]
    internal enum PrincipalParseFlags
    {
        NONE = 0,
        KRB5_PRINCIPAL_PARSE_NO_REALM = 0x01,
        KRB5_PRINCIPAL_PARSE_REQUIRE_REALM = 0x02,
        KRB5_PRINCIPAL_PARSE_ENTERPRISE = 0x04,
        KRB5_PRINCIPAL_PARSE_IGNORE_REALM = 0x08,
        KRB5_PRINCIPAL_PARSE_NO_DEF_REALM = 0x10,
    }
}

using System;
using System.Runtime.InteropServices;
using System.Security.Authentication;

namespace PSOpenAD.Native;

internal static class Kerberos
{
    public const string LIB_KRB5 = "PSOpenAD.libkrb5";

    private const int KRB5_CONFIG_NODEFREALM = -1765328160;

    [DllImport(LIB_KRB5)]
    public static extern void krb5_free_default_realm(
        SafeKrb5Context context,
        IntPtr lrealm);

    [DllImport(LIB_KRB5)]
    public static extern void krb5_free_context(
        IntPtr context);

    [DllImport(LIB_KRB5)]
    public static extern void krb5_free_error_message(
        SafeKrb5Context ctx,
        IntPtr msg);

    [DllImport(LIB_KRB5)]
    public static extern int krb5_get_default_realm(
        SafeKrb5Context context,
        out SafeKrb5Realm lrealm);

    [DllImport(LIB_KRB5)]
    public static extern int krb5_get_default_principal(
        SafeKrb5Context context,
        out SafeKrb5Principal principal);

    [DllImport(LIB_KRB5)]
    public static extern int krb5_unparse_name(
        SafeKrb5Context context,
        SafeKrb5Principal principal,
        out IntPtr name);

    [DllImport(LIB_KRB5)]
    public static extern void krb5_free_principal(
        SafeKrb5Context context,
        IntPtr principal);

    [DllImport(LIB_KRB5)]
    public static extern SafeKrb5ErrorMessage krb5_get_error_message(
        SafeKrb5Context ctx,
        int code);

    [DllImport(LIB_KRB5)]
    public static extern int krb5_init_context(
        out SafeKrb5Context context);

    [DllImport(LIB_KRB5)]
    public static extern void krb5_xfree(
        IntPtr ptr);

    /// <summary>Get the default realm of the Kerberos context.</summary>
    /// <remarks>
    /// The API first tries to look up the default realm configured in the krb5.conf file of the environment. If
    /// the file does not exist or does not contain a default_realm entry then it will attempt to extract the
    /// default realm from the default principal. If that fails then a KerberosException is thrown.
    /// </remarks>
    /// <param name="context">The Kerberos context handle.</param>
    /// <returns>The default realm.</returns>
    /// <exception cref="KerberosException">Kerberos error reported, most likely no realm was found.</exception>
    /// <see href="https://web.mit.edu/kerberos/krb5-latest/doc/appdev/refs/api/krb5_get_default_realm.html">krb5_get_default_realm</see>
    public static string GetDefaultRealm(SafeKrb5Context context)
    {
        int res = krb5_get_default_realm(context, out var realm);
        if (res == 0)
        {
            realm.Context = context;
            using (realm)
                return realm.ToString();
        }

        if (res == KRB5_CONFIG_NODEFREALM)
        {
            using SafeKrb5Principal principal = context.GetDefaultPrincipal();
            string name = principal.ToString();
            int atIndex = name.IndexOf('@');
            if (atIndex != -1)
                return name[(atIndex + 1)..];
        }

        throw new KerberosException(context, res, "krb5_get_default_realm");
    }

    /// <summary>Create Kerberos Context.</summary>
    /// <returns>The Kerberos context handle.</returns>
    /// <see href="https://web.mit.edu/kerberos/krb5-devel/doc/appdev/refs/api/krb5_init_context.html">krb5_init_context</see>
    public static SafeKrb5Context InitContext()
    {
        krb5_init_context(out var ctx);
        return ctx;
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

    public SafeKrb5Principal GetDefaultPrincipal()
    {
        int res = Kerberos.krb5_get_default_principal(this, out var principal);
        if (res != 0)
            throw new KerberosException(this, res, "krb5_get_default_principal");

        principal.Context = this;
        return principal;
    }
}

internal class SafeKrb5Principal : SafeHandle
{
    internal SafeKrb5Context Context = new();

    internal SafeKrb5Principal() : base(IntPtr.Zero, true) { }

    public override bool IsInvalid => handle == IntPtr.Zero;

    public override string ToString()
    {
        int res = Kerberos.krb5_unparse_name(Context, this, out var name);
        if (res != 0)
            throw new KerberosException(Context, res, "krb5_unparse_name");

        string? result =  Marshal.PtrToStringUTF8(name);

        Kerberos.krb5_xfree(name);

        return result ?? "";
    }

    protected override bool ReleaseHandle()
    {
        Kerberos.krb5_free_principal(Context, handle);
        return true;
    }
}

internal class SafeKrb5ErrorMessage : SafeHandle
{
    internal SafeKrb5Context Context = new();

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

internal class SafeKrb5Realm : SafeHandle
{
    internal SafeKrb5Context Context = new();

    internal SafeKrb5Realm() : base(IntPtr.Zero, true) { }

    public override bool IsInvalid => handle == IntPtr.Zero;

    public override string ToString()
    {
        return Marshal.PtrToStringUTF8(handle) ?? "";
    }

    protected override bool ReleaseHandle()
    {
        // Heimdal does not include krb5_free_default_realm and instead uses krb5_xfree.
        if (GlobalState.GssapiProvider == GssapiProvider.MIT)
        {
            Kerberos.krb5_free_default_realm(Context, handle);
        }
        else
        {
            Kerberos.krb5_xfree(handle);
        }

        return true;
    }
}

public class KerberosException : AuthenticationException
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

using System.Diagnostics.CodeAnalysis;
using System.Runtime.InteropServices;

namespace PSOpenAD.Native;

internal partial class Kerberos
{
    [LibraryImport(LIB_KRB5)]
    private static partial int krb5_cc_get_principal(
        SafeKrb5Context context,
        SafeKrb5CCache ccache,
        out nint principal);

    public static bool TryGetCCachePrincipal(
        SafeKrb5Context context,
        SafeKrb5CCache ccache,
        [NotNullWhen(true)] out SafeKrb5Principal? principal,
        [NotNullWhen(false)] out KerberosException? exception)
    {
        principal = null;
        exception = null;

        int res = krb5_cc_get_principal(context, ccache, out nint principalPtr);
        if (res != 0)
        {
            exception = KerberosException.Create(context, res, nameof(krb5_cc_get_principal));
            return false;
        }

        principal = new(context, principalPtr);
        return true;
    }
}

internal class SafeKrb5Principal : SafeHandle
{
    private SafeKrb5Context _context;

    internal SafeKrb5Principal(SafeKrb5Context context, nint principal) : base(principal, true)
    {
        _context = context;
    }

    public override bool IsInvalid => handle == nint.Zero;

    protected override bool ReleaseHandle()
    {
        Kerberos.krb5_free_principal(_context, handle);
        return true;
    }
}

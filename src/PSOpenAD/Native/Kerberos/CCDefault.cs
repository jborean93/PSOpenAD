using System.Diagnostics.CodeAnalysis;
using System.Runtime.InteropServices;

namespace PSOpenAD.Native;

internal partial class Kerberos
{
    [LibraryImport(LIB_KRB5)]
    private static partial int krb5_cc_default(
        SafeKrb5Context context,
        out nint ccache);

    public static bool TryGetDefaultCCache(
        SafeKrb5Context context,
        [NotNullWhen(true)] out SafeKrb5CCache? ccache,
        [NotNullWhen(false)] out KerberosException? exception)
    {
        ccache = null;
        exception = null;

        int res = krb5_cc_default(context, out nint ccachePtr);
        if (res != 0)
        {
            exception = KerberosException.Create(context, res, nameof(krb5_cc_default));
            return false;
        }

        ccache = new(context, ccachePtr);
        return true;
    }
}

internal class SafeKrb5CCache : SafeHandle
{
    private SafeKrb5Context _context;

    internal SafeKrb5CCache(SafeKrb5Context context, nint ccache) : base(ccache, true)
    {
        _context = context;
    }

    public override bool IsInvalid => handle == nint.Zero;

    protected override bool ReleaseHandle()
    {
        Kerberos.krb5_cc_close(_context, handle);
        return true;
    }
}

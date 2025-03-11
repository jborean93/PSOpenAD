using System.Diagnostics.CodeAnalysis;
using System.Runtime.InteropServices;

namespace PSOpenAD.Native;

internal partial class Kerberos
{
    [LibraryImport(LIB_KRB5)]
    private static partial int krb5_get_default_realm(
        SafeKrb5Context context,
        out nint lrealm);

    public static bool TryGetDefaultRealm(
        SafeKrb5Context context,
        [NotNullWhen(true)] out string? realm,
        [NotNullWhen(false)] out KerberosException? exception)
    {
        realm = null;
        exception = null;

        int res = krb5_get_default_realm(context, out nint realmPtr);
        if (res != 0)
        {
            exception = KerberosException.Create(context, res, nameof(krb5_get_default_realm));
            return false;
        }

        try
        {
            realm = Marshal.PtrToStringUTF8(realmPtr) ?? "";
            return true;
        }
        finally
        {
            FreeDefaultRealm(context, realmPtr);
        }
    }
}

using System.Runtime.InteropServices;

namespace PSOpenAD.Native;

internal partial class Kerberos
{
    [LibraryImport(LIB_KRB5)]
    private static partial void krb5_free_default_realm(
        SafeKrb5Context context,
        nint lrealm);

    public static void FreeDefaultRealm(
        SafeKrb5Context context,
        nint realm)
    {
        if (GlobalState.GetFromTLS().GssapiProvider == GssapiProvider.MIT)
        {
            krb5_free_default_realm(context, realm);
        }
        else
        {
            krb5_xfree(realm);
        }
    }
}

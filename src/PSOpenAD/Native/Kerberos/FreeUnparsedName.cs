using System.Runtime.InteropServices;

namespace PSOpenAD.Native;

internal partial class Kerberos
{
    [LibraryImport(LIB_KRB5)]
    private static partial void krb5_free_unparsed_name(
        SafeKrb5Context context,
        nint name);

    public static void FreeUnparsedName(
        SafeKrb5Context context,
        nint name)
    {
        if (GlobalState.GetFromTLS().GssapiProvider == GssapiProvider.MIT)
        {
            krb5_free_unparsed_name(context, name);
        }
        else
        {
            krb5_xfree(name);
        }
    }
}

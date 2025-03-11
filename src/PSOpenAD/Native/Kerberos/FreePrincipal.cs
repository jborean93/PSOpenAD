using System.Runtime.InteropServices;

namespace PSOpenAD.Native;

internal partial class Kerberos
{
    [LibraryImport(LIB_KRB5)]
    public static partial void krb5_free_principal(
        SafeKrb5Context context,
        nint principal);
}

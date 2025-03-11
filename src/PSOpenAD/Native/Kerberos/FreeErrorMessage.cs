using System.Runtime.InteropServices;

namespace PSOpenAD.Native;

internal partial class Kerberos
{
    [LibraryImport(LIB_KRB5)]
    private static partial void krb5_free_error_message(
        SafeKrb5Context context,
        nint msg);
}

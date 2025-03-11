using System.Runtime.InteropServices;

namespace PSOpenAD.Native;

internal partial class Kerberos
{
    [LibraryImport(LIB_KRB5)]
    public static partial int krb5_cc_close(
        SafeKrb5Context context,
        nint ccache);
}

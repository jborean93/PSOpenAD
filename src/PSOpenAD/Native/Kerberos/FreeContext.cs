using System.Runtime.InteropServices;

namespace PSOpenAD.Native;

internal partial class Kerberos
{
    [LibraryImport(LIB_KRB5)]
    internal static partial void krb5_free_context(
        nint context);
}

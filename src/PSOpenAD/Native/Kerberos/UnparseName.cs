using System.Diagnostics.CodeAnalysis;
using System.Runtime.InteropServices;

namespace PSOpenAD.Native;

internal partial class Kerberos
{
    [LibraryImport(LIB_KRB5)]
    private static partial int krb5_unparse_name(
        SafeKrb5Context context,
        SafeKrb5Principal principal,
        out nint name);

    public static bool TryUnparseName(
        SafeKrb5Context context,
        SafeKrb5Principal principal,
        [NotNullWhen(true)] out string? name,
        [NotNullWhen(false)] out KerberosException? exception)
    {
        name = null;
        exception = null;

        int res = krb5_unparse_name(context, principal, out nint namePtr);
        if (res != 0)
        {
            exception = KerberosException.Create(context, res, nameof(krb5_unparse_name));
            return false;
        }

        name = Marshal.PtrToStringUTF8(namePtr) ?? "";
        return true;
    }
}

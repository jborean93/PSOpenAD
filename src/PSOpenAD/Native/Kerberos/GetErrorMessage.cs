using System.Runtime.InteropServices;

namespace PSOpenAD.Native;

internal partial class Kerberos
{
    [LibraryImport(LIB_KRB5)]
    private static partial nint krb5_get_error_message(
        SafeKrb5Context context,
        int code);

    public static string? GetErrorMessage(
        SafeKrb5Context context,
        int code)
    {
        nint msg = krb5_get_error_message(context, code);

        try
        {
            return Marshal.PtrToStringUTF8(msg);
        }
        finally
        {
            krb5_free_error_message(context, msg);
        }
    }
}

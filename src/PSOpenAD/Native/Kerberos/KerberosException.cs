using System.Security.Authentication;

namespace PSOpenAD.Native;

internal class KerberosException : AuthenticationException
{
    public int ErrorCode { get; }

    private KerberosException(
        string message,
        int error) : base(message)
    {
        ErrorCode = error;
    }

    public static KerberosException Create(
        SafeKrb5Context context,
        int error,
        string method)
    {
        string krb5Err = Kerberos.GetErrorMessage(context, error) ?? "Unknown error";
        string msg = $"{method} failed ({error}) - {krb5Err}";
        return new(msg, error);
    }
}

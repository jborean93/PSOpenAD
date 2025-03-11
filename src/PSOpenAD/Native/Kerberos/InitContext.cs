using System.Runtime.InteropServices;

namespace PSOpenAD.Native;

internal partial class Kerberos
{
    public const string LIB_KRB5 = "PSOpenAD.libkrb5";

    [LibraryImport(LIB_KRB5)]
    private static partial int krb5_init_context(
        out nint context);

    public static SafeKrb5Context InitContext()
    {
        int res = krb5_init_context(out var contextHandle);
        SafeKrb5Context context = new(contextHandle);
        if (res != 0)
        {
            throw KerberosException.Create(context, res, nameof(krb5_init_context));
        }

        return context;
    }
}

internal class SafeKrb5Context : SafeHandle
{
    internal SafeKrb5Context(nint context) : base(context, true) { }

    public override bool IsInvalid => handle == nint.Zero;

    protected override bool ReleaseHandle()
    {
        Kerberos.krb5_free_context(handle);
        return true;
    }
}

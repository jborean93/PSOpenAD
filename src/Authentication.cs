using System.Collections.Generic;

namespace PSOpenAD
{
    public enum AuthenticationMethod
    {
        Anonymous,
        Simple,
        Negotiate,
        Kerberos,
    }

    public sealed class AuthenticationProvider
    {
        public AuthenticationMethod Method { get; }
        public string NativeId { get; }
        public bool Available { get; }
        public bool CanSign { get; }
        public bool SupportsCB { get; }
        public string Details { get; }

        public AuthenticationProvider(AuthenticationMethod method, string nativeId, bool available, bool canSign,
            bool supportsCB, string details)
        {
            Method = method;
            NativeId = nativeId;
            Available = available;
            CanSign = canSign;
            SupportsCB = supportsCB;
            Details = details;
        }
    }

    internal static class ClientAuthentication
    {
        // Populated by OnImport
        public static List<AuthenticationProvider> Providers = new List<AuthenticationProvider>();
    }
}

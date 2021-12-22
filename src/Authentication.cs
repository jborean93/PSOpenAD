namespace PSOpenAD
{
    public enum AuthenticationMethod
    {
        Default,
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
}

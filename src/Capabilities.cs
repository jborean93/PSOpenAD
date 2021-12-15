using System;
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

    internal static class ClientCapabilities
    {
        private static readonly Lazy<Dictionary<string, string>> _saslFeatures =
            new Lazy<Dictionary<string, string>>(() => GetSaslFeatures());

        private static readonly Lazy<AuthenticationMethod[]> _saslMechs =
            new Lazy<AuthenticationMethod[]>(() => GetSaslMechs());

        public static AuthenticationMethod[] AuthenticationMethods => _saslMechs.Value;

        public static bool SupportsChannelBindings
        {
            get => _saslFeatures.Value.ContainsKey("test");
        }

        private static AuthenticationMethod[] GetSaslMechs()
        {
            List<AuthenticationMethod> authMethods = new List<AuthenticationMethod>();
            authMethods.Add(AuthenticationMethod.Anonymous);
            authMethods.Add(AuthenticationMethod.Simple);

            try
            {
                List<string> availableMechs = OpenLDAP.GetOptionSaslMechList(new SafeLdapHandle());
                if (availableMechs.Contains("GSSAPI"))
                    authMethods.Add(AuthenticationMethod.Kerberos);

                if (availableMechs.Contains("GSS-SPNEGO"))
                    authMethods.Add(AuthenticationMethod.Negotiate);
            }
            catch (LDAPException) { }

            return authMethods.ToArray();
        }

        private static Dictionary<string, string> GetSaslFeatures()
        {
            Sasl.ClientInit();

            List<string> availableMechs = OpenLDAP.GetOptionSaslMechList(new SafeLdapHandle());
            foreach (string mech in availableMechs)
            {
                Sasl.ClientPluginInfo(mech);
            }

            return new Dictionary<string, string>();
        }
    }
}

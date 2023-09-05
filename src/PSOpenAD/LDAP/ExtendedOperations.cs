using System;

namespace PSOpenAD.LDAP;

public static class ExtendedOperations
{
    public const string LDAP_SERVER_FAST_BIND_OID = "1.2.840.113556.1.4.1781";
    public const string LDAP_SERVER_BATCH_REQUEST_OID = "1.2.840.113556.1.4.2212";
    public const string LDAP_TTL_REFRESH_OID = "1.3.6.1.4.1.1466.101.119.1";
    public const string LDAP_SERVER_START_TLS_OID = "1.3.6.1.4.1.1466.20037";
    public const string LDAP_SERVER_WHO_AM_I_OID = "1.3.6.1.4.1.4203.1.11.3";
}

using System;

namespace PSOpenAD;

/// <summary>The result from a LDAP Whoami request operation.</summary>
public sealed class WhoamiResult
{
    /// <summary>The username without the u: prefix found in the raw result.</summary>
    public string UserName => RawUserName.StartsWith("u:") ? RawUserName[2..] : RawUserName;

    /// <summary>The LDAP connection URI used for the whoami request.</summary>
    public Uri Uri { get; }

    /// <summary>The domain controller the request was sent to.</summary>
    public string DomainController { get; }

    /// <summary>The authentication method used for the LDAP session that did the whoami request.</summary>
    public AuthenticationMethod Authentication { get; }

    /// <summary>The raw result from the LDAP whoami request.</summary>
    public string RawUserName { get; }

    internal WhoamiResult(string result, Uri uri, string domainController, AuthenticationMethod authentication)
    {
        RawUserName = result;
        Uri = uri;
        DomainController = domainController;
        Authentication = authentication;
    }
}

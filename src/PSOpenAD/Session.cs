using PSOpenAD.LDAP;
using System;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;

namespace PSOpenAD;

/// <summary>Advanced session options for an OpenAD Session.</summary>
public sealed class OpenADSessionOptions
{
    /// <summary>Disables encryption when using Negotiate/Kerberos auth over LDAP.</summary>
    public bool NoEncryption { get; set; }

    /// <summary>Disables signing when using Negotiate/Kerberos auth over LDAP (requires NoEncryption).</summary>
    public bool NoSigning { get; set; }

    /// <summary>Will not bind the auth context to the LDAPS/StartTLS channel for legacy hosts.</summary>
    public bool NoChannelBinding { get; set; }

    /// <summary>Disables any server cert validation checks performed for LDAPS/StartTLS.</summary>
    public bool SkipCertificateCheck { get; set; }

    /// <summary>The maximum time to wait, in milliseconds, to initially connect to the target.</summary>
    public Int32 ConnectTimeout { get; set; } = 180000; // 3 Minutes

    /// <summary>The maximum time to wait, in milliseconds, to wait for a request to return.</summary>
    public Int32 OperationTimeout { get; set; } = 180000;

    /// <summary>Local path that incoming and outgoing LDAP messages will be logged to.</summary>
    public string? TracePath { get; set; }

    /// <summary>Used for TLS client certificate authentication.</summary>
    public X509Certificate? ClientCertificate { get; set; }
}

/// <summary>The OpenADSession class used to encapsulate a session with the caller.</summary>
public sealed class OpenADSession
{
    /// <summary>The unique identifier for the session.</summary>
    public int Id { get; }

    /// <summary>The URI that was used to connect to the domain controller.</summary>
    public Uri Uri { get; }

    /// <summary>The authentication method used when connecting to the domain controller.</summary>
    public AuthenticationMethod Authentication { get; }

    /// <summary>Whether the network traffic is signed in some way.</summary>
    public bool IsSigned { get; }

    /// <summary>Whether the network traffic is encrypted in some way.</summary>
    public bool IsEncrypted { get; }

    /// <summary>The maximum time to wait, in milliseconds, to wait for a request to return.</summary>
    public Int32 OperationTimeout { get; }

    /// <summary>The default naming context used as the base for subsequent LDAP requests.</summary>
    public string DefaultNamingContext { get; }

    /// <summary>Whether the connection has been closed or is still open.</summary>
    public bool IsClosed => Connection.IsClosed;

    // FIXME: Should reflect when the connection is closed.
    /// <summary>The LDAP session state.</summary>
    public SessionState State => Connection.Session.State;

    /// <summary>The domain controller DNS name that was used for the connection.</summary>
    public string DomainController { get; }

    /// <summary>The connection used for this session.</summary>
    internal IADConnection Connection { get; }

    /// <summary>The LDAP state manager for this session.</summary>
    internal LDAPSession Ldap => Connection.Session;

    /// <summary>Schema metadata for this connection.</summary>
    internal SchemaMetadata SchemaMetadata { get; }

    /// <summary>Extended control OIDs supported by the server.</summary>
    internal string[] SupportedControls { get; }

    internal OpenADSession(IADConnection connection, Uri uri, AuthenticationMethod auth, bool isSigned,
        bool isEncrypted, int operationTimeout, string defaultNamingContext, SchemaMetadata schema,
        string[] supportedControls, string dcDnsHostName)
    {
        Id = GlobalState.SessionCounter;
        GlobalState.SessionCounter++;

        Connection = connection;
        Uri = uri;
        Authentication = auth;
        IsSigned = isSigned;
        IsEncrypted = isEncrypted;
        OperationTimeout = operationTimeout;
        DefaultNamingContext = defaultNamingContext;
        DomainController = dcDnsHostName;
        SchemaMetadata = schema;
        SupportedControls = supportedControls;

        GlobalState.Sessions.Add(this);
        connection.Session.StateChanged += OnStateChanged;
    }

    internal void Close()
    {
        Connection.Dispose();
        Connection.Session.StateChanged -= OnStateChanged;
    }

    private void OnStateChanged(object? sender, SessionState state)
    {
        if (state == SessionState.Closed)
        {
            GlobalState.Sessions.Remove(this);
        }
    }
}

internal static class GlobalState
{
    /// <summary>Client authentication provider details.</summary>
    public static Dictionary<AuthenticationMethod, AuthenticationProvider> Providers = new();

    /// <summary>List of sessions that have been opened by the client.</summary>
    public static List<OpenADSession> Sessions = new();

    /// <summary>Keeps the current session count used to uniquely identify each new session.</summary>
    public static int SessionCounter = 1;

    /// <summary>Information about LDAP classes and their attributes.</summary>
    public static SchemaMetadata? SchemaMetadata;

    /// <summary>The GSSAPI/SSPI provider that is used.</summary>
    public static GssapiProvider GssapiProvider;

    /// <summary>The default domain controller hostname to use when none was provided.</summary>
    public static Uri? DefaultDC;

    /// <summary>If the default DC couldn't be detected this stores the details.</summary>
    public static string? DefaultDCError;
}

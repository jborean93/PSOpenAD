using PSOpenAD.LDAP;
using System;
using System.Buffers;
using System.Collections.Generic;
using System.Linq;
using System.Management.Automation;
using System.Net.Security;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

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
}

/// <summary>The OpenADSession class used to encapsulate a session with the caller.</summary>
public sealed class OpenADSession
{
    /// <summary>The URI that was used to connect to the domain controller.</summary>
    public Uri Uri { get; }

    /// <summary>The authentication method used when connecting to the domain controller.</summary>
    public AuthenticationMethod Authentication { get; }

    /// <summary>Whether the network traffic is signed in some way.</summary>
    public bool IsSigned { get; }

    /// <summary>Whether the network traffic is encrypted in some way.</summary>
    public bool IsEncrypted { get; }

    /// <summary>The default naming context used as the base for subsequent LDAP requests.</summary>
    public string DefaultNamingContext { get; }

    /// <summary>Whether the connection has been closed or is still open.</summary>
    public bool IsClosed => Connection.IsClosed;

    internal OpenADConnection Connection { get; }

    internal LDAPSession Ldap => Connection.Session;

    internal AttributeTransformer AttributeTransformer { get; }

    internal OpenADSession(OpenADConnection connection, Uri uri, AuthenticationMethod auth,
        bool isSigned, bool isEncrypted, string defaultNamingContext, AttributeTransformer transformer)
    {
        Connection = connection;
        Uri = uri;
        Authentication = auth;
        IsSigned = isSigned;
        IsEncrypted = isEncrypted;
        DefaultNamingContext = defaultNamingContext;
        AttributeTransformer = transformer;
    }

    internal void Close()
    {
        Connection.Dispose();
    }
}

internal sealed class OpenADSessionFactory
{
    internal static OpenADSession CreateOrUseDefault(Uri uri, PSCredential? credential, AuthenticationMethod auth,
        bool startTls, OpenADSessionOptions sessionOptions, CancellationToken cancelToken = default,
        PSCmdlet? cmdlet = null)
    {
        // Use this as an opportunity to prune connections that have been closed unexpectantly.
        OpenADSession? session = null;
        foreach (string connectionUri in GlobalState.ImplicitSessions.Keys)
        {
            OpenADSession currentSession = GlobalState.ImplicitSessions[connectionUri];

            if (currentSession.IsClosed)
            {
                currentSession.Close();
                GlobalState.ImplicitSessions.Remove(connectionUri);
                continue;
            }

            if (connectionUri == uri.ToString())
                session = currentSession;
        }

        if (session != null)
        {
            cmdlet?.WriteVerbose("Using cached OpenADSession");
            return session;
        }
        else
        {
            session = Create(uri, credential, auth, startTls, sessionOptions, cancelToken, cmdlet: cmdlet);
            GlobalState.AddSession(uri.ToString(), session);

            return session;
        }
    }

    internal static OpenADSession Create(Uri uri, PSCredential? credential, AuthenticationMethod auth,
        bool startTls, OpenADSessionOptions sessionOptions, CancellationToken cancelToken = default,
        PSCmdlet? cmdlet = null)
    {
        cmdlet?.WriteVerbose($"Connecting to {uri}");
        TcpClient client = new();
        Task connectTask = client.ConnectAsync(uri.DnsSafeHost, uri.Port);
        if (!connectTask.Wait(sessionOptions.ConnectTimeout, cancelToken))
            throw new TimeoutException();
        connectTask.GetAwaiter().GetResult();

        OpenADConnection connection = new(client, client.GetStream(), new LDAPSession(),
            sessionOptions.OperationTimeout);
        try
        {
            bool transportIsTls = false;
            ChannelBindings? channelBindings = null;
            if (startTls || uri.Scheme.Equals("ldaps", StringComparison.InvariantCultureIgnoreCase))
            {
                transportIsTls = true;
                channelBindings = ProcessTlsOptions(connection, uri, startTls, sessionOptions, cancelToken, cmdlet);
            }

            auth = Authenticate(connection, uri, auth, credential, channelBindings, transportIsTls, sessionOptions,
                cancelToken, cmdlet);

            // Attempt to get the default naming context.
            string defaultNamingContext = "";
            string subschemaSubentry = "";
            foreach (SearchResultEntry searchRes in Operations.LdapSearchRequest(connection, "", SearchScope.Base,
                0, sessionOptions.OperationTimeout, new FilterPresent("objectClass"),
                new string[] { "defaultNamingContext", "subschemaSubentry" }, null, cancelToken, cmdlet))
            {
                foreach (PartialAttribute attribute in searchRes.Attributes)
                {
                    if (attribute.Name == "defaultNamingContext")
                        defaultNamingContext = Encoding.UTF8.GetString(attribute.Values[0]);

                    else if (attribute.Name == "subschemaSubentry")
                        subschemaSubentry = Encoding.UTF8.GetString(attribute.Values[0]);
                }
            }

            // Attempt to get the schema info of the host so the code can parse the raw LDAP attribute values into
            // the required PowerShell type.
            AttributeTransformer attrInfo = QueryAttributeTypes(connection, subschemaSubentry, sessionOptions,
                cancelToken, cmdlet);

            return new OpenADSession(connection, uri, auth, transportIsTls || connection.Sign,
                transportIsTls || connection.Encrypt, defaultNamingContext, attrInfo);
        }
        catch
        {
            connection.Dispose();
            throw;
        }
    }

    /// <summary>Performs StartTLS on the LDAP connection and completes the TLS handshake.</summary>
    /// <param name="connection">The OpenAD connection.</param>
    /// <param name="uri">The URI used for the connection.</param>
    /// <param name="startTls">Whether to perform StartTLS on an LDAP connection.</param>
    /// <param name="sessionOptions">More session options to control the TLS behaviour.</param>
    /// <param name="cancelToken">Cancellation token for any network requests.</param>
    /// <param name="cmdlet">PSCmdlet to write verbose records to.</param>
    /// <returns>The channel binding data used with SASL authentication if available.</returns>
    private static ChannelBindings? ProcessTlsOptions(OpenADConnection connection, Uri uri, bool startTls,
        OpenADSessionOptions sessionOptions, CancellationToken cancelToken, PSCmdlet? cmdlet)
    {
        if (sessionOptions.NoEncryption || sessionOptions.NoSigning)
            throw new ArgumentException("Cannot disable encryption or signatures for TLS based connection");

        if (startTls && uri.Scheme.Equals("ldaps", StringComparison.InvariantCultureIgnoreCase))
        {
            throw new ArgumentException("Cannot use StartTLS over an LDAPS connection");
        }
        else if (startTls)
        {
            cmdlet?.WriteVerbose("Sending StartTLS request to the server");
            int startTlsId = connection.Session.ExtendedRequest("1.3.6.1.4.1.1466.20037");

            ExtendedResponse extResp = (ExtendedResponse)connection.WaitForMessage(startTlsId,
                cancelToken: cancelToken);
            connection.RemoveMessageQueue(startTlsId);
            if (extResp.Result.ResultCode != LDAPResultCode.Success)
                throw new LDAPException(extResp.Result);
        }

        cmdlet?.WriteVerbose("Performing TLS handshake on connection");
        SslClientAuthenticationOptions authOptions = new()
        {
            TargetHost = uri.DnsSafeHost,
        };
        if (sessionOptions.SkipCertificateCheck)
        {
            authOptions.RemoteCertificateValidationCallback =
                ((sender, ceritificate, chain, SslPolicyErrors) => true);
        }

        SslStream tls = connection.SetTlsStream(authOptions, cancelToken);

        ChannelBindings? cbt = null;
        if (!sessionOptions.NoChannelBinding)
            cbt = GetTlsChannelBindings(tls);

        return cbt;
    }

    /// <summary>Get channel binding data for SASL auth</summary>
    /// <remarks>
    /// While .NET has it's own function to retrieve this value it returns an opaque pointer with no publicly
    /// documented structure. To avoid using any internal implementation details this just does the same work to
    /// achieve the same result.
    /// </remarks>
    /// <param name="tls">The SslStream that has been authenticated.</param>
    /// <returns>The channel binding data if available.</returns>
    private static ChannelBindings? GetTlsChannelBindings(SslStream tls)
    {
        using X509Certificate2 cert = new(tls.RemoteCertificate);

        byte[] certHash;
        switch (cert.SignatureAlgorithm.Value)
        {
            case "2.16.840.1.101.3.4.2.2": // SHA384
            case "1.2.840.10045.4.3.3": // SHA384ECDSA
            case "1.2.840.113549.1.1.12": // SHA384RSA
                using (SHA384 hasher = SHA384.Create())
                    certHash = hasher.ComputeHash(cert.RawData);
                break;

            case "2.16.840.1.101.3.4.2.3": // SHA512
            case "1.2.840.10045.4.3.4": // SHA512ECDSA
            case "1.2.840.113549.1.1.13": // SHA512RSA
                using (SHA512 hasher = SHA512.Create())
                    certHash = hasher.ComputeHash(cert.RawData);
                break;

            // Older protocols default to SHA256, use this as a catch all in case of a weird algorithm.
            default:
                using (SHA256 hasher = SHA256.Create())
                    certHash = hasher.ComputeHash(cert.RawData);
                break;
        }

        byte[] prefix = Encoding.UTF8.GetBytes("tls-server-end-point:");
        byte[] finalCB = new byte[prefix.Length + certHash.Length];
        Array.Copy(prefix, 0, finalCB, 0, prefix.Length);
        Array.Copy(certHash, 0, finalCB, prefix.Length, certHash.Length);

        return new ChannelBindings()
        {
            ApplicationData = finalCB,
        };
    }

    /// <summary>Authenticates with the LDAP server.</summary>
    /// <param name="connection">The LDAP connection to authenticate against.</param>
    /// <param name="uri">The URI used for the connection, this is used for GSSAPI as the target SPN.</param>
    /// <param name="auth">The authentication mechanism to use.</param>
    /// <param name="credential">The explicit username and password to authenticate with.</param>
    /// <param name="channelBindings">TLS channel bindings to use with GSSAPI authentication.</param>
    /// <param name="transportIsTls">Whether the underlying transport is protected with TLS.</param>
    /// <param name="sessionOptions">More session options to control the auth behaviour.</param>
    /// <param name="cancelToken">Cancellation token for any network requests.</param>
    /// <param name="cmdlet">PSCmdlet to write verbose records to.</param>
    /// <returns>The authentication method used</returns>
    private static AuthenticationMethod Authenticate(OpenADConnection connection, Uri uri,
        AuthenticationMethod auth, PSCredential? credential, ChannelBindings? channelBindings,
        bool transportIsTls, OpenADSessionOptions sessionOptions, CancellationToken cancelToken, PSCmdlet? cmdlet)
    {
        if (auth == AuthenticationMethod.Default)
        {
            // Always favour Negotiate auth if it is available, otherwise use Simple if both a credential and the
            // exchange would be encrypted. If all else fails use an anonymous bind.
            AuthenticationProvider nego = GlobalState.Providers[AuthenticationMethod.Negotiate];
            if (nego.Available)
            {
                auth = AuthenticationMethod.Negotiate;
            }
            else if (credential != null && transportIsTls)
            {
                auth = AuthenticationMethod.Simple;
            }
            else
            {
                auth = AuthenticationMethod.Anonymous;
            }

            cmdlet?.WriteVerbose($"Default authentiation mechanism has been set to {auth}");
        }

        AuthenticationProvider selectedAuth = GlobalState.Providers[auth];
        if (!selectedAuth.Available)
        {
            string msg = $"Authentication {selectedAuth.Method} is not available";
            if (!string.IsNullOrWhiteSpace(selectedAuth.Details))
                msg += $" - ${selectedAuth.Details}";
            throw new ArgumentException(msg);
        }

        string username = credential?.UserName ?? "";
        string password = credential?.GetNetworkCredential().Password ?? "";

        if (auth == AuthenticationMethod.Kerberos || auth == AuthenticationMethod.Negotiate)
        {
            bool integrity = !(transportIsTls || sessionOptions.NoSigning);
            bool confidentiality = !(transportIsTls || sessionOptions.NoEncryption);

            // GSS-SPNEGO on non-Windows cannot disable confidentiality without also disabling integrity so warn
            // the caller if this set of session options have been set. Technically NTLM on Windows also applies
            // here but we cannot know what SPNEGO will choose until after the auth is done so just ignore that.
            if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows) &&
                auth == AuthenticationMethod.Negotiate && sessionOptions.NoEncryption
                && !sessionOptions.NoSigning)
            {
                cmdlet?.WriteWarning("-AuthType Negotiate cannot disable encryption without disabling signing");
                // Will be set to false above, need to ensure that it is true unless TLS is used as the packets
                // must be encrypted for Negotiate unless both integrity is disabled.
                confidentiality = !transportIsTls;
            }
            if (sessionOptions.NoSigning && !sessionOptions.NoEncryption)
            {
                cmdlet?.WriteWarning("Cannot disable signatures and not encryption");
            }

            SecurityContext context;
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                string targetSpn = $"ldap/{uri.DnsSafeHost}";
                context = new SspiContext(username, password, auth, targetSpn, channelBindings, integrity,
                    confidentiality);
            }
            else
            {
                string targetSpn = $"ldap@{uri.DnsSafeHost}";
                context = new GssapiContext(username, password, auth, targetSpn, channelBindings, integrity,
                    confidentiality);
            }
            SaslAuth(connection, context, selectedAuth.SaslId, integrity, confidentiality,
                cancelToken);

            connection.SecurityContext = context;
            connection.Sign = integrity;
            connection.Encrypt = confidentiality;

            cmdlet?.WriteVerbose($"SASL auth complete - Will Sign {integrity} - Will Encrypt {confidentiality}");
        }
        else
        {
            SimpleAuth(connection, username, password, cancelToken);
        }

        return selectedAuth.Method;
    }

    /// <summary>Performs a SIMPLE bind to the LDAP server</summary>
    /// <param name="connection">The LDAP connection to perform the bind on.</param>
    /// <param name="username">The username used for the SIMPLE bind.</param>
    /// <param name="password">The password used for the SIMPLE bind.</param>
    /// <param name="cancelToken">Token to cancel any network IO waits</param>
    private static void SimpleAuth(OpenADConnection connection, string? username, string? password,
        CancellationToken cancelToken)
    {
        int bindId = connection.Session.Bind(username ?? "", password ?? "");

        BindResponse response = (BindResponse)connection.WaitForMessage(bindId, cancelToken: cancelToken);
        connection.RemoveMessageQueue(bindId);
        if (response.Result.ResultCode != LDAPResultCode.Success)
        {
            throw new LDAPException(response.Result);
        }
    }

    /// <summary>Performs a SASL bind to the LDAP server</summary>
    /// <param name="connection">The LDAP connection to perform the bind on.</param>
    /// <param name="context">The security context used to generate the SASL tokens and wrap the data.</param>
    /// <param name="saslMech">The name of the SASL mechanism used</param>
    /// <param name="integrity">Whether to negotiate message signatures using the auth context.</param>
    /// <param name="confidentiality">Whether to negotiate message encryption using the auth context.</param>
    /// <param name="cancelToken">Token to cancel any network IO waits</param>
    private static void SaslAuth(OpenADConnection connection, SecurityContext context,
        string saslMech, bool integrity, bool confidentiality, CancellationToken cancelToken)
    {
        byte[]? inputToken = null;
        int saslId;

        BindResponse response;
        while (inputToken == null || inputToken.Length > 0)
        {
            byte[] outputToken = context.Step(inputToken: inputToken);
            if (outputToken.Length == 0 && context.Complete)
                break;

            saslId = connection.Session.SaslBind("", saslMech, outputToken);

            response = (BindResponse)connection.WaitForMessage(saslId, cancelToken: cancelToken);
            connection.RemoveMessageQueue(saslId);
            if (response.Result.ResultCode != LDAPResultCode.Success &&
                response.Result.ResultCode != LDAPResultCode.SaslBindInProgress)
            {
                throw new LDAPException(response.Result);
            }

            inputToken = response.ServerSaslCreds;
        }

        if (integrity && !context.IntegrityAvailable || confidentiality && !context.ConfidentialityAvailable)
        {
            throw new AuthenticationException(
                "Failed to negotiate encryption or signing capabilities with the server during authentication.");
        }

        // The only SASL mech supported that does further work is the GSSAPI mech. This behaviour is defined in
        // RF 4752 - Section 3.1 - https://datatracker.ietf.org/doc/html/rfc4752#section-3.1
        if (saslMech != "GSSAPI")
            return;

        saslId = connection.Session.SaslBind("", saslMech, Array.Empty<byte>());
        response = (BindResponse)connection.WaitForMessage(saslId, cancelToken: cancelToken);
        connection.RemoveMessageQueue(saslId);
        if (response.Result.ResultCode != LDAPResultCode.Success &&
            response.Result.ResultCode != LDAPResultCode.SaslBindInProgress)
        {
            throw new LDAPException(response.Result);
        }

        inputToken = response.ServerSaslCreds;

        if (inputToken == null)
        {
            throw new AuthenticationException(
                "Expecting input token to verify security context with SASL GSSAPI mech");
        }

        byte[] contextInfo = context.Unwrap(inputToken);
        if (contextInfo.Length != 4)
        {
            throw new AuthenticationException(
                "Input token for SASL GSSAPI negotiation was not the expected size");
        }

        SASLSecurityFlags serverFlags = (SASLSecurityFlags)contextInfo[0];
        contextInfo[0] = 0;
        if (BitConverter.IsLittleEndian)
            Array.Reverse(contextInfo);
        uint maxServerMessageLength = BitConverter.ToUInt32(contextInfo);

        if (serverFlags == SASLSecurityFlags.NoSecurity && maxServerMessageLength != 0)
        {
            throw new AuthenticationException(
                $"Server did not response with 0 for the server message length but was {maxServerMessageLength}");
        }

        // Build the client flags based on what the client requests
        SASLSecurityFlags clientFlags = SASLSecurityFlags.NoSecurity;
        if (integrity && confidentiality)
            clientFlags |= SASLSecurityFlags.Confidentiality | SASLSecurityFlags.Integrity;
        else if (integrity)
            clientFlags |= SASLSecurityFlags.Integrity;

        uint maxClientMessageLength = 0;
        if (clientFlags != SASLSecurityFlags.NoSecurity)
        {
            // Windows doesn't have a max wrap size func, just send back the server value.
            maxClientMessageLength = RuntimeInformation.IsOSPlatform(OSPlatform.Windows)
                ? maxServerMessageLength
                : context.MaxWrapSize(maxServerMessageLength, confidentiality);
        }

        byte[] clientContextInfo = BitConverter.GetBytes(maxClientMessageLength);
        if (BitConverter.IsLittleEndian)
            Array.Reverse(clientContextInfo);
        clientContextInfo[0] = (byte)clientFlags;

        byte[] wrappedResp = context.Wrap(clientContextInfo, false);

        saslId = connection.Session.SaslBind("", saslMech, wrappedResp);
        response = (BindResponse)connection.WaitForMessage(saslId, cancelToken: cancelToken);
        connection.RemoveMessageQueue(saslId);
        if (response.Result.ResultCode != LDAPResultCode.Success &&
            response.Result.ResultCode != LDAPResultCode.SaslBindInProgress)
        {
            throw new LDAPException(response.Result);
        }
    }

    /// <summary>Gets the attribute schema information.</summary>
    /// <param name="connection">The LDAP connection to perform the search on on.</param>
    /// <param name="subschemaSubentry">The DN of the subschemaSubentry to query.</param>
    /// <param name="cancelToken">Token to cancel any network IO waits</param>
    /// <param name="cmdlet">PSCmdlet used to write verbose records.</param>
    /// <returns>The attribute information from the parse schema information.</returns>
    private static AttributeTransformer QueryAttributeTypes(OpenADConnection connection, string subschemaSubentry,
        OpenADSessionOptions sessionOptions, CancellationToken cancelToken, PSCmdlet? cmdlet)
    {
        Dictionary<string, AttributeTypeDescription> attrInfo = new();

        foreach (SearchResultEntry result in Operations.LdapSearchRequest(connection, subschemaSubentry,
            SearchScope.Base, 0, sessionOptions.OperationTimeout, new FilterPresent("objectClass"),
            new string[] { "attributeTypes" }, null, cancelToken, cmdlet))
        {
            PartialAttribute? attribute = result.Attributes.Where(a => a.Name == "attributeTypes").First();
            if (attribute != null)
            {
                foreach (byte[] value in attribute.Values)
                {
                    string rawValue = Encoding.UTF8.GetString(value);

                    // Neither Syntax or Name should be undefined but they are technically optional in the spec.
                    // Write a verbose entry to help with future debugging if this becomes more of an issue.
                    AttributeTypeDescription attrTypes = new(rawValue);
                    if (String.IsNullOrEmpty(attrTypes.Syntax))
                    {
                        cmdlet?.WriteVerbose($"Failed to parse SYNTAX: '{rawValue}'");
                        continue;
                    }
                    if (String.IsNullOrEmpty(attrTypes.Name))
                    {
                        cmdlet?.WriteVerbose($"Failed to parse NAME: '{rawValue}'");
                        continue;
                    }

                    attrInfo[attrTypes.Name] = attrTypes;
                }
            }
        }

        return new AttributeTransformer(attrInfo);
    }
}

internal static class GlobalState
{
    // Populated by OnImport
    public static Dictionary<AuthenticationMethod, AuthenticationProvider> Providers = new();

    public static string? DefaultRealm;

    public static Dictionary<string, OpenADSession> ImplicitSessions = new(StringComparer.OrdinalIgnoreCase);

    public static bool GssapiIsHeimdal;

    public static void AddSession(string id, OpenADSession session)
    {
        if (ImplicitSessions.ContainsKey(id))
            ImplicitSessions[id].Close();

        ImplicitSessions[id] = session;
    }
}

using PSOpenAD.LDAP;
using System;
using System.Collections.Generic;
using System.Globalization;
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

namespace PSOpenAD.Module;

internal sealed class OpenADSessionFactory
{
    internal static OpenADSession? CreateOrUseDefault(string? server, PSCredential? credential,
        AuthenticationMethod auth, bool startTls, OpenADSessionOptions sessionOptions, CancellationToken cancelToken,
        PSCmdlet cmdlet, bool skipCache = false)
    {
        Uri ldapUri;
        if (string.IsNullOrEmpty(server))
        {
            if (GlobalState.DefaultDC == null)
            {
                string msg = "Cannot determine default realm for implicit domain controller.";
                if (!string.IsNullOrEmpty(GlobalState.DefaultDCError))
                {
                    msg += $" {GlobalState.DefaultDCError}";
                }
                cmdlet.WriteError(new ErrorRecord(
                    new ArgumentException(msg),
                    "NoImplicitDomainController",
                    ErrorCategory.InvalidArgument,
                    null));
                return null;
            }

            ldapUri = GlobalState.DefaultDC;
        }
        else if (server.StartsWith("ldap://", true, CultureInfo.InvariantCulture) ||
            server.StartsWith("ldaps://", true, CultureInfo.InvariantCulture))
        {
            ldapUri = new Uri(server);
        }
        else if (server.Contains(':'))
        {
            string[] serverSplit = server.Split(':', 2);
            if (int.TryParse(serverSplit[1], out var port))
            {
                string scheme = port == 636 || port == 3269 ? "ldaps" : "ldap";
                ldapUri = new Uri($"{scheme}://{server}/");
            }
            else
            {
                string msg = "Expecting server in the format of hostname or hostname:port with port as an integer";
                cmdlet.WriteError(new ErrorRecord(
                    new ArgumentException(msg),
                    "InvalidServerPort",
                    ErrorCategory.InvalidArgument,
                    null));
                return null;
            }
        }
        else
        {
            ldapUri = new Uri($"ldap://{server}:389/");
        }

        OpenADSession? session = null;
        if (!skipCache)
        {
            session = GlobalState.Sessions.Find(s => s.Uri == ldapUri);
        }

        if (session == null)
        {
            try
            {
                return Create(ldapUri, credential, auth, startTls, sessionOptions, cancelToken, cmdlet: cmdlet);
            }
            catch (LDAPException e)
            {
                cmdlet.WriteError(new ErrorRecord(e, "LDAPError", ErrorCategory.ProtocolError, null));
            }
            catch (AuthenticationException e)
            {
                cmdlet.WriteError(new ErrorRecord(e, "AuthError", ErrorCategory.AuthenticationError, null));
            }
            catch (ArgumentException e)
            {
                cmdlet.WriteError(new ErrorRecord(e, "InvalidParameter", ErrorCategory.InvalidArgument, null));
            }

            return null;
        }
        else
        {
            cmdlet.WriteVerbose("Using cached OpenADSession");
            return session;
        }
    }

    internal static OpenADSession Create(
        Uri uri,
        PSCredential? credential,
        AuthenticationMethod auth,
        bool startTls,
        OpenADSessionOptions sessionOptions,
        CancellationToken cancelToken,
        PSCmdlet cmdlet
    )
    {
        if (auth == AuthenticationMethod.Certificate && sessionOptions.ClientCertificate is null)
        {
            throw new ArgumentException(
                "Certificate authentication is requested but ClientCertificate has not been set");
        }

        cmdlet.WriteVerbose($"Connecting to {uri}");
        TcpClient client = new();
        Task connectTask = client.ConnectAsync(uri.DnsSafeHost, uri.Port);
        if (!connectTask.Wait(sessionOptions.ConnectTimeout, cancelToken))
            throw new TimeoutException();
        connectTask.GetAwaiter().GetResult();

        OpenADConnection connection = new(
            client,
            client.GetStream(),
            sessionOptions.OperationTimeout,
            sessionOptions.TracePath
        );
        try
        {
            bool transportIsTls = false;
            ChannelBindings? channelBindings = null;
            if (startTls || uri.Scheme.Equals("ldaps", StringComparison.InvariantCultureIgnoreCase))
            {
                transportIsTls = true;
                channelBindings = ProcessTlsOptions(connection, uri, startTls, sessionOptions, cancelToken, cmdlet);
            }
            else if (auth == AuthenticationMethod.Certificate)
            {
                throw new ArgumentException("Certificate authentication is requested but TLS is not being used");
            }

            auth = Authenticate(
                connection,
                uri,
                auth,
                credential,
                channelBindings,
                transportIsTls,
                sessionOptions,
                cancelToken,
                cmdlet,
                out var authSigned,
                out var authEncrypted
            );

            // Attempt to get the default naming context.
            string defaultNamingContext = "";
            string dnsHostName = "Unknown";
            string subschemaSubentry = "";
            string[] supportedControls = Array.Empty<string>();
            string[] baseAttributes = new[]
            {
                "defaultNamingContext", "dnsHostName", "subschemaSubentry", "supportedControl",
            };
            foreach (SearchResultEntry searchRes in Operations.LdapSearchRequest(connection, "", SearchScope.Base,
                0, sessionOptions.OperationTimeout, new FilterPresent("objectClass"),
                baseAttributes, null, cancelToken, cmdlet, true))
            {
                foreach (PartialAttribute attribute in searchRes.Attributes)
                {
                    if (attribute.Name == "defaultNamingContext")
                    {
                        defaultNamingContext = Encoding.UTF8.GetString(attribute.Values[0]);
                    }
                    else if (attribute.Name == "dnsHostName")
                    {
                        dnsHostName = Encoding.UTF8.GetString(attribute.Values[0]);
                    }
                    else if (attribute.Name == "subschemaSubentry")
                    {
                        subschemaSubentry = Encoding.UTF8.GetString(attribute.Values[0]);
                    }
                    else if (attribute.Name == "supportedControl")
                    {
                        supportedControls = attribute.Values.Select(v => Encoding.UTF8.GetString(v)).ToArray();
                    }
                }
            }

            // Attempt to get the schema info of the host so the code can parse the raw LDAP attribute values into
            // the required PowerShell type.
            SchemaMetadata schema = QuerySchema(connection, subschemaSubentry, sessionOptions, cancelToken, cmdlet);

            return new OpenADSession(connection, uri, auth, transportIsTls || authSigned,
                transportIsTls || authEncrypted, sessionOptions.OperationTimeout, defaultNamingContext, schema,
                supportedControls, dnsHostName);
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
    private static ChannelBindings? ProcessTlsOptions(IADConnection connection, Uri uri, bool startTls,
        OpenADSessionOptions sessionOptions, CancellationToken cancelToken, PSCmdlet cmdlet)
    {
        if (sessionOptions.NoEncryption || sessionOptions.NoSigning)
            throw new ArgumentException("Cannot disable encryption or signatures for TLS based connection");

        if (startTls && uri.Scheme.Equals("ldaps", StringComparison.InvariantCultureIgnoreCase))
        {
            throw new ArgumentException("Cannot use StartTLS over an LDAPS connection");
        }
        else if (startTls)
        {
            cmdlet.WriteVerbose("Sending StartTLS request to the server");
            int startTlsId = connection.Session.ExtendedRequest(ExtendedOperations.LDAP_SERVER_START_TLS_OID);

            ExtendedResponse extResp = (ExtendedResponse)connection.WaitForMessage(startTlsId,
                cancelToken: cancelToken);
            connection.RemoveMessageQueue(startTlsId);
            if (extResp.Result.ResultCode != LDAPResultCode.Success)
                throw new LDAPException(extResp.Result);
        }

        cmdlet.WriteVerbose("Performing TLS handshake on connection");
        SslClientAuthenticationOptions authOptions = new()
        {
            TargetHost = uri.DnsSafeHost,
        };
        if (sessionOptions.SkipCertificateCheck)
        {
            authOptions.RemoteCertificateValidationCallback = (_1, _2, _3, _4) => true;
        }

        if (sessionOptions.ClientCertificate is not null)
        {
            authOptions.LocalCertificateSelectionCallback = (_1, _2, _3, _4, _5) => sessionOptions.ClientCertificate;
        }

        SslStream tls = connection.SetTlsStream(authOptions, cancelToken);

        ChannelBindings? cbt = null;
        if (!sessionOptions.NoChannelBinding && tls.RemoteCertificate != null)
        {
            using X509Certificate2 cert = (X509Certificate2)tls.RemoteCertificate;
            cbt = GetTlsChannelBindings(cert);
        }

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
    private static ChannelBindings? GetTlsChannelBindings(X509Certificate2 cert)
    {
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
    /// <param name="signed">Whether the auth context will sign the messages.</param>
    /// <param name="encrypted">Whether the auth context will encrypt the messages.</param>
    /// <returns>The authentication method used</returns>
    private static AuthenticationMethod Authenticate(
        IADConnection connection,
        Uri uri,
        AuthenticationMethod auth,
        PSCredential? credential,
        ChannelBindings? channelBindings,
        bool transportIsTls,
        OpenADSessionOptions sessionOptions,
        CancellationToken cancelToken,
        PSCmdlet cmdlet,
        out bool signed,
        out bool encrypted
    )
    {
        if (credential == PSCredential.Empty)
        {
            credential = null;
        }

        if (auth == AuthenticationMethod.Default)
        {
            // Use Certificate if a client certificate is specified, otherwise favour Negotiate auth if it is
            // available. Otherwise use Simple if both a credential and the exchange would be encrypted. If all else
            // fails use an anonymous bind.
            AuthenticationProvider nego = GlobalState.Providers[AuthenticationMethod.Negotiate];
            if (sessionOptions.ClientCertificate is not null && transportIsTls)
            {
                auth = AuthenticationMethod.Certificate;
            }
            else if (nego.Available)
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

            cmdlet.WriteVerbose($"Default authentication mechanism has been set to {auth}");
        }

        AuthenticationProvider selectedAuth = GlobalState.Providers[auth];
        if (!selectedAuth.Available)
        {
            string msg = $"Authentication {selectedAuth.Method} is not available";
            if (!string.IsNullOrWhiteSpace(selectedAuth.Details))
                msg += $" - {selectedAuth.Details}";
            throw new ArgumentException(msg);
        }

        string username = credential?.UserName ?? "";
        string password = credential?.GetNetworkCredential().Password ?? "";

        signed = false;
        encrypted = false;
        if (auth == AuthenticationMethod.Kerberos || auth == AuthenticationMethod.Negotiate)
        {
            signed = !(transportIsTls || sessionOptions.NoSigning);
            encrypted = !(transportIsTls || sessionOptions.NoEncryption);

            // GSS-SPNEGO on non-Windows cannot disable confidentiality without also disabling integrity so warn
            // the caller if this set of session options have been set. Technically NTLM on Windows also applies
            // here but we cannot know what SPNEGO will choose until after the auth is done so just ignore that.
            if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows) &&
                auth == AuthenticationMethod.Negotiate && sessionOptions.NoEncryption
                && !sessionOptions.NoSigning)
            {
                cmdlet.WriteWarning("-AuthType Negotiate cannot disable encryption without disabling signing");
                // Will be set to false above, need to ensure that it is true unless TLS is used as the packets
                // must be encrypted for Negotiate unless both integrity is disabled.
                encrypted = !transportIsTls;
            }
            if (sessionOptions.NoSigning && !sessionOptions.NoEncryption)
            {
                cmdlet.WriteWarning("Cannot disable signatures and not encryption");
            }

            SecurityContext context;
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                string targetSpn = $"ldap/{uri.DnsSafeHost}";
                context = new SspiContext(username, password, auth, targetSpn, channelBindings, signed,
                    encrypted);
            }
            else
            {
                string targetSpn = $"ldap@{uri.DnsSafeHost}";
                context = new GssapiContext(username, password, auth, targetSpn, channelBindings, signed,
                    encrypted);
            }
            SaslAuth(connection, context, selectedAuth.SaslId, signed, encrypted,
                cancelToken);

            connection.AssociateSecurityContext(context, signed, encrypted);
            cmdlet.WriteVerbose($"SASL auth complete - Will Sign {signed} - Will Encrypt {encrypted}");
        }
        else if (auth == AuthenticationMethod.Certificate)
        {
            // If using LDAPS then AD will automatically bind against the client certificate sent in the handshake.
            // No extra SASL binds are needed, if you attempt to do so it will fail. When using StartTLS over LDAP an
            // external bind must be done to tell the server to use the certificate exchanged in the TLS handshake.
            // https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/8e73932f-70cf-46d6-88b1-8d9f86235e81
            if (uri.Scheme.Equals("ldap", StringComparison.InvariantCultureIgnoreCase))
            {
                ExternalContext context = new();
                SaslAuth(connection, context, selectedAuth.SaslId, false, false, cancelToken);
            }
            else
            {
                connection.Session.State = LDAP.SessionState.Opened;
            }
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
    private static void SimpleAuth(IADConnection connection, string? username, string? password,
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
    private static void SaslAuth(IADConnection connection, SecurityContext context,
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

        if ((integrity && !context.IntegrityAvailable) || (confidentiality && !context.ConfidentialityAvailable))
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

    /// <summary>Gets the attribute and class schema information.</summary>
    /// <param name="connection">The LDAP connection to perform the search on.</param>
    /// <param name="subschemaSubentry">The DN of the subschemaSubentry to query.</param>
    /// <param name="sessionOption">The session options to control the query timeout.</param>
    /// <param name="cancelToken">Token to cancel any network IO waits</param>
    /// <param name="cmdlet">PSCmdlet used to write verbose records.</param>
    /// <returns>The schema information.</returns>
    private static SchemaMetadata QuerySchema(IADConnection connection, string subschemaSubentry,
        OpenADSessionOptions sessionOptions, CancellationToken cancelToken, PSCmdlet? cmdlet)
    {
        Dictionary<string, AttributeTypeDescription> attrInfo = new();
        Dictionary<string, DITContentRuleDescription> ditInfo = new();
        Dictionary<string, ObjectClassDescription> classInfo = new();

        foreach (SearchResultEntry result in Operations.LdapSearchRequest(connection, subschemaSubentry,
            SearchScope.Base, 0, sessionOptions.OperationTimeout, new FilterPresent("objectClass"),
            new string[] { "attributeTypes", "dITContentRules", "objectClasses" }, null, cancelToken, cmdlet, true))
        {
            foreach (PartialAttribute attribute in result.Attributes)
            {
                foreach (byte[] value in attribute.Values)
                {
                    string rawValue = Encoding.UTF8.GetString(value);

                    if (attribute.Name == "attributeTypes")
                    {
                        AttributeTypeDescription attrTypes = new(rawValue);
                        attrInfo[attrTypes.Names[0]] = attrTypes;
                    }
                    else if (attribute.Name == "dITContentRules")
                    {
                        DITContentRuleDescription ditRule = new(rawValue);
                        ditInfo[ditRule.OID] = ditRule;
                    }
                    else if (attribute.Name == "objectClasses")
                    {
                        ObjectClassDescription objClass = new(rawValue);
                        classInfo[objClass.Names[0]] = objClass;
                    }
                }
            }
        }

        return new SchemaMetadata(attrInfo, ditInfo, classInfo);
    }
}

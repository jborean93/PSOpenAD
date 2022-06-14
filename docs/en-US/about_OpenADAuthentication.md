# Open AD Authentication
## about_OpenADAuthentication

# SHORT DESCRIPTION
Authentication with an LDAP/AD server is critical to having a secure and trustworthy connection to perform various AD operations.
The way authentication is handled is very tightly coupled with the operating system and authentication provider availablility can differ based on how the client environment is set up.

# LONG DESCRIPTION
There are 4 different types of authentication methods that are supported by LDAP:

+ Anonymous

+ Simple

+ Kerberos

+ Negotiate

The `Anonymous` and `Simple` authentication methods are available to all clients but may not be useable in every scenario.
The `Kerberos` and `Negotiate` authentication methods are implemented through SSPI on Windows and GSSAPI on Linux/macOS.
The availability of these two authentication methods outside of Windows depends on whether the GSSAPI libraries have been installed and configured on the client host.
To see what authentication methods are available to `PSOpenAD`, run `Get-OpenADAuthSupport`.
This cmdlet will output each authentication method and whether it is available for use by the module.

# ANONYMOUS AUTH
Anonymous authentication is simply binding to the LDAP connection without any username or password.
The operations that can be performed on an anonymous connection are very limited and usually is to just query the LDAP RootDSE metadata.
Anonymous authentication is used when Negotiate/Kerberos auth is unavailable and Simple auth cannot be used due to security concerns.

# SIMPLE AUTH
Simple authentication is sending the username and password in plaintext as the bind operation.
As the credentials are send without any encryption this authentication method only be used on a `StartTLS` or `LDAPS` connection.
A `StartTLS` or `LDAPS` connection will encrypt all the traffic on the connection stopping anyone from seeing the credentials that were exchanged.
Microsoft Active Directory servers have now started to reject simple auth without the TLS protection offered by `StartTLS` or `LDAPS`.
This option should be avoided unless either `Kerberos` or `Negotiate` authentication is not available and `StartTLS` or `LDAPS` is available.

# KERBEROS AUTH
Kerberos authentication uses special ticket to authenticate the client against the server endpoint.
The client will either use an already retrieved Ticket Granting Ticket (`TGT`) for a domain user or use the explicitly passed in `PSCredential` object to retrieve it's own `TGT`.
THe client will then use the `TGT` to authenticate itself against the server and then finally validate the server's identity.
Once complete it will perform one more step to negotiate whether the subsequent LDAP packets will be signed or encrypted over a standard LDAP connection.

Both Windows and macOS/Linux can use an explicit credential or rely on OS specific credential caches for the authentication user.
See `CREDENTIAL CACHE` below for more details on using a cached credential with this module.

Kerberos authentication over LDAP refers to the `GSSAPI` Simple Authentication and Security Layer (`SASL`) mechanism.
See `GSSAPI` below for more details on setting up and configuring `GSSAPI` on macOS/Linux.

# NEGOTIATE AUTH
Negotiate authentication is a slight modification to Kerberos authentication detailed above.
Negotiate auth covers Kerberos auth but also offers NTLM authentication if Kerberos is available.
The available of NTLM is also dependent on the OS being used, it will always be available for Windows but for macOS/Linux it might require more packages to be installed.
Negotiate authentication also skips the final signing/encryption negotiation done by Kerberos auth.
The data is still encrypted or signed by default it just requires less network requests to negotiate than Kerberos auth.

Negotiate authentication over LDAP refers to the `GSS-SPNEGO` mechanism.
It is recommended to use Negotiate auth over Kerberos unless only Kerberos authentication is desired.

# CERTIFICATE AUTH
Certificate authentication uses an X.509 certificate presented by the client that used for authenticatoin.
Typically this certificate is mapped to an account on the server.
For Microsoft Active Directory servers, the certificate is either created by the Active Directory Certificate Services for a user, implicit mapping.
It could also be a certificate that is manually mapped to a domain account and trusted in the `NTAuthStore`, explicit mapping.
The client provides a certificate containing a private key for use with the TLS handshake and the identity the certificate is mapped to is used for authentication.
This client certificate is set through the `New-OpenADSessionOption -ClientCertificate $cert` parameter when creating the session.

Certificate authentication over LDAP refers to the `EXTERNAL` mechanism.
This can only be used when communicating over LDAP with `StartTLS` enabled or an `LDAPS` connection.

# ENCRYPTION
While `StartTLS` or `LDAPS` connections will encrypt all the LDAP traffic between the client and server, normal `LDAP` connections use the authentication provider to provide encryption/signing.
Neither the `Anonymous` or `Simple` authentication method can encrypt/sign the data and thus should only be used on a `StartTLS` or `LDAPS` connection.
The `Kerberos` and `Negotiate` authentication method can both encrypt or just sign the data with them defaulting to encryption.
Encryption can be disabled (signing only) by setting the OpenAD session option `New-OpenADSessionOption -NoEncryption`.
Both encryption and signatures can be disabled by setting the OpenAD session options `New-OpenADSessionOption -NoEncryption -NoSigning`.
Disabling either encryption or signing should only be done for debugging or diagnostic purposes.

Microsoft Active Directory servers have recently started enforcing at least signed connections through either Kerberos/Negotiate signing or `StartTLS`/`LDAPS` connections.
Encryption is also enabled by default but is not typically something required by Active Directory.
Note that encryption cannot be disabled with `StartTLS`/`LDAPS`, this is something enforce by the `TLS` protocol that they both utilise.

# CHANNEL BINDING
Channel binding is a special feature available to `Kerberos` and `Negotiate` authentication methods when connecting over `StartTLS` or `LDAPS`.
The channel binding mechanism will create a special hash of the TLS certificate exposed by the server and embed it into the Kerberos or NTLM token that is exchanged with the server.
This is a useful mechanism to ensure that the client is talking directly to the server it has requsted and there isn't any middle man intercepting the TLS traffic.

Microsoft Active Directory servers can be configured to enforce channel binding for `Kerberos` or `Negotiate auth.
This should be done automatically by the OpenAD client but if for some reason it is causing troubles with authentication it can be disabled with `New-OpenADSessionOption -NoChannelBinding`.

# CREDENTIAL CACHE
One nice feature of `Kerberos` and `Negotiate` auth is the ability to authenticate to a server without providing any explicit credentials.
It is able to do this by using a credential stored in a cache available to the user.

On Windows a credential can be retrieved from two locations:

+ The current user

+ Windows Credential Manager

The current user credential can be used in most interactive scenarios and is typically how the ActiveDirectory cmdlets work when talking to Active Directory.
The current user credential is not available if working from a network logon, this is known as the credential delegation or [double hop](https://docs.microsoft.com/en-us/powershell/scripting/learn/remoting/ps-remoting-second-hop?view=powershell-7.2) problem.
The Windows Credential Manager can also cache credentials and are selected based on the server it was registered with.

On macOS/Linux a credential can be cached based on the GSSAPI implementation that is in use.
Typically this is done by calling `kinit` to retrieve a TGT for a particular user and PSOpenAD is then able to use that TGT for future authentication attempts.
There are numerous mechanisms that can automate this process to ensure that a ticket is retrieved during the logon process just like on Windows or it can just be called manually.

The `klist` command can be used to view the current set of cached credentials that are available, if any are.

If no credentials were specified when creating the OpenAD session and a cached credential is unavailable then the authentication attempt will fail.

# GSSAPI
This section does not apply to Windows as it includes `SSPI` in the box.

MacOS also ships it's own GSSAPI provider by default but it may require futher configuration to get it working.
Each Linux distribution may also ship with a copy of the `GSSAPI` libraries but that isn't guaranteed.
The following commands can be used to install the Kerberos library on the various Linux distributions.

```bash
# Debian/Ubuntu
apt-get install krb5-user

# Centos/RHEL/Fedora
[dnf|yum] install krb5-workstation

# Arch Linux
pacman -S gcc krb5
```

Once installed Kerberos can be configured with the `/etc/krb5.conf` file.
A very barebones `krb5.conf` file is as follows.

```ini
[libdefaults]
  default_realm = DOMAIN.COM

[realms]
  DOMAIN.COM = {
    kdc = dc01.domain.com
    admin_server = dc01.domain.com
  }

[domain_realm]
  domain.com = DOMAIN.COM
  .domain.com = DOMAIN.COM
```

As long as the client can resolve the fully qualified domain name then PSOpenAD should be able to use Kerberos auth.
Use `kinit username@DOMAIN.COM` to test out that the client is able to retrieve a credential to verify that the client is able to successfully use Kerberos auth.
Please note, the client host does not need to be joined to the domain to use Kerberos auth.
The minimum requires are:

+ The Kerberos libraries are installed

+ The client's DNS setup is able to resolve the domain names to actual hostnames

+ The time on the client is within 5 minutes of the domain controller configured

+ The `/etc/krb5.conf` may be required if DNS is unable to resolve the SRV query `_ldap._tcp.dc._msdcs.domain.com`

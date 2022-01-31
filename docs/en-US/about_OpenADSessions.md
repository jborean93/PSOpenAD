# Open AD Sessions
## about_OpenADSessions

# SHORT DESCRIPTION
Being able to communicate with the LDAP server is a crucial part of getting PSOpenAD to work.
The main communication in this module is done through an OpenAD session which is explained further in this document.

# LONG DESCRIPTION
To perform any LDAP operation, such as a search request, a connection needs to created and authenticated between the client and server.
The PSOpenAD module relies on three different mechanisms to manage these sessions:

+ Through explicitly created sessions with `New-OpenADSession` passed in with `-Session`

+ Using a cached connection for the server specified

+ Creating a new session for the server specified and caching it for later use

If no explicit session or server was specified for an operation then PSOpenAD will attempt to locate the domain controller hostname through a mechanism called DC Locator.
This is essentially a connection created on demand to the server specified by the DC Locator mechanism and then cached for further use.
The DC Locator process is expanded further below under `DC LOCATOR`.
While using the DC Locator to search and then subsequently cache the session is the simplest method to use from a script perspective it relies heavily on having the client's environment to be set up for it to work.
Due to the potential complexities involved in this setup the other options may be preferable.

Sessions are designed to act in a similar manner to PSSessions with `Invoke-Command`, `Enter-PSSession`, etc.
They are either creating with `New-OpenADSession` and used with the `-Session` parameter or they can be implicitly created by the cmdlet based on the `-Server` value passed in.

# CACHED SESSIONS
When a session is created it is automatically added to a process wide connection pool.
This means that subsequent connections will attempt to use the connection in the cache if the requested server name matches what is in the pool instead of creating a brand new connection on each request.
The benefits to this is that it avoids the overhead of creating new connections on each cmdlet call.
The `Get-OpenADSession` cmdlet can be used to retrieve a list of cached connections that are in the pool.

To avoid using any cached session use the `-Session` parameter to pass in the explicit session that is retrieved through either `New-OpenADSession` or `Get-OpenADSession`.

# TLS
LDAP can be futher protected using TLS using `StartTLS` over `LDAP` or just a straight `LDAPS` connection.
While `StartTLS` operates over the standard `LDAP` port it effectively provides a similar level of protection to an `LDAPS` connection.
Both of these scenarios will use Transport Layer Security (`TLS`) to provide server verification and encryption to the data exchanged between the client and server.
They both require the server to be configured with TLS which varies across implementation to implementation.

Part of the TLS handshake is having the client verify the identity of the server that is exposed in the certificate it presented.
This process is the same that occurs for connecting to a `HTTPS` backed website.
PSOpenAD relies on .NET to perform the identity checks on the certificate, how to trust certain certificates and managing certificate authorities is not covered under the scope of these docs.
While not recommended, certificate verification can be disabled with `New-OpenADSessionOption -SkipCertificateCheck`.
This should be reserved for testing scenarios when using self signed certificates only.

# DC LOCATOR
If no session or server was specified when performing and LDAP/AD operation then PSOpenAD will attempt to connect to the endpoint it has determined to be the environment domain controller (`DC`).

On Windows the default DC is retrieved through the [DsGetDcNameW](https://docs.microsoft.com/en-us/windows/win32/api/dsgetdc/nf-dsgetdc-dsgetdcnamew) API call.
The Windows DC locator process is covered in more detail in [this MS article](https://social.technet.microsoft.com/wiki/contents/articles/24457.how-domain-controllers-are-located-in-windows.aspx).
Ultimately it performs some DNS SRV lookups and uses the site configuration to determine the best DC to use.
Typically this just works and the end result is a domain joined Windows client will always have a default DC to connect to.

Linux and macOS performs a more rudimentary search to try and find the default DC.
It will first check if the Kerberos API was available and get the value of the `default_realm` setting in the `krb5.conf`.
If there is no `krb5.conf` found or `default_realm` is not set then the `default_realm` is set to the domain part of the local hostname.
If the `default_realm` was successfully retrieved (or determined by the local hostname) PSOpenAD does an `SRV` lookup for `_ldap._tcp.dc._msdcs.{default_realm}`.
If any records are returned the default DC is set to the record with the preferred property and weight.

If any of these steps fail then no default DC is available and PSOpenAD is only able to create a connection when an explicit server or connection uri was provided.

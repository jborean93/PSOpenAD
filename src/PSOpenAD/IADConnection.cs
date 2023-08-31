using PSOpenAD.LDAP;
using System;
using System.Net.Security;
using System.Threading;

namespace PSOpenAD;

internal interface IADConnection : IDisposable
{
    /// <summary>Gets the LDAP session associated with this connection.</summary>
    public LDAPSession Session { get; }

    /// <summary>
    /// Whether the connection has been closed or not.
    /// </summary>
    public bool IsClosed { get; }

    /// <summary>Wait for a response from the LDAP server.</summary>
    /// <param name="messageId">Wait for the response for the request that generated this id.</param>
    /// <param name="timeout">Override the default timeout to wait for a response.</param>
    /// <param name="cancelToken">Cancel token used to cancel the wait operation.</param>
    /// <returns>The LDAP message response.</returns>
    public LDAPMessage WaitForMessage(
        int messageId,
        int? timeout = null,
        CancellationToken cancelToken = default
    );

    /// <summary>Remove the wait queue for this request message identifier.</summary>
    /// <remarks>This should be called once all the messages for this request has been received.</remarks>
    /// <param name="messageId">The request message id to remove from the queue.</param>
    public void RemoveMessageQueue(
        int messageId
    );

    /// <summary>Upgrades the socket stream to a TLS wrapped one.</summary>
    /// <remarks>
    /// This is used for a StartTLS or LDAPS connection to replace the socket stream with a TLS one.
    /// </remarks>
    /// <param name="authOptions">The TLS client authentication details used during the handshake.</param>
    /// <param name="cancelToken">Token to cancel the TLS handshake connection.</param>
    public SslStream SetTlsStream(
        SslClientAuthenticationOptions authOptions,
        CancellationToken cancelToken = default
    );

    /// <summary>
    /// Associates a Negotiate session with the connection.
    /// </summary>
    /// <param name="context">The security context.</param>
    /// <param name="sign">Whether signing is required.</param>
    /// <param name="encrypt">Whether encryption is required.</param>
    public void AssociateSecurityContext(
        SecurityContext context,
        bool sign,
        bool encrypt
    );
}

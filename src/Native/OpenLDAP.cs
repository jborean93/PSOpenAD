using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace PSOpenAD.Native
{
    internal static partial class Helpers
    {
        [StructLayout(LayoutKind.Sequential)]
        public struct berval
        {
            public int bv_len;
            public IntPtr bv_val;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct LDAPControl
        {
            public IntPtr ldctl_oid;
            public berval ldctl_value;
            [MarshalAs(UnmanagedType.U1)] public bool ldctl_iscritical;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct timeval
        {
            public int tv_sec;
            public int tv_usec;
        }
    }

    internal class LDAPControl
    {
        public const string LDAP_SERVER_SHOW_DELETED_OID = "1.2.840.113556.1.4.417";
        public const string LDAP_SERVER_SHOW_DEACTIVATED_LINK_OID = "1.2.840.113556.1.4.2065";

        public string Oid { get; }
        public byte[]? Value { get; }
        public bool IsCritical { get; }

        public LDAPControl(string oid, byte[]? value, bool isCritical)
        {
            Oid = oid;
            Value = value;
            IsCritical = isCritical;
        }
    }

    internal static class OpenLDAP
    {
        public const string LIB_LDAP = "PSOpenAD.libldap";

        public delegate int LDAP_SASL_INTERACT_PROC(
            IntPtr ld,
            int flags,
            IntPtr defaults,
            IntPtr interact);

        [DllImport(LIB_LDAP)]
        public static extern void ber_free(
            IntPtr ber,
            int freebuf);

        [DllImport(LIB_LDAP)]
        public static extern void ldap_controls_free(
            IntPtr ctrls);

        [DllImport(LIB_LDAP)]
        public static extern int ldap_count_values_len(
            SafeLdapValueArray vals);

        [DllImport(LIB_LDAP)]
        public static extern IntPtr ldap_err2string(
            int error);

        [DllImport(LIB_LDAP)]
        public static extern SafeLdapMemory ldap_first_attribute(
            SafeLdapHandle ld,
            IntPtr entry,
            out SafeBerElement berptr);

        [DllImport(LIB_LDAP)]
        public static extern IntPtr ldap_first_entry(
            SafeLdapHandle ld,
            SafeLdapMessage result);

        [DllImport(LIB_LDAP)]
        public static extern int ldap_get_option(
            SafeLdapHandle ld,
            LDAPOption option,
            out IntPtr outvalue);

        [DllImport(LIB_LDAP)]
        public static extern int ldap_get_option(
            SafeLdapHandle ld,
            LDAPOption option,
            out int outvalue);

        [DllImport(LIB_LDAP)]
        public static extern int ldap_get_option(
            SafeLdapHandle ld,
            LDAPOption option,
            out SafeLdapMemory outvalue);

        [DllImport(LIB_LDAP)]
        public static extern SafeLdapValueArray ldap_get_values_len(
            SafeLdapHandle ld,
            IntPtr entry,
            string attr);

        [DllImport(LIB_LDAP)]
        public static extern int ldap_initialize(
            out SafeLdapHandle ldp,
            string uri);

        [DllImport(LIB_LDAP)]
        public static extern void ldap_memfree(
            IntPtr p);

        [DllImport(LIB_LDAP)]
        public static extern void ldap_memvfree(
            IntPtr p);

        [DllImport(LIB_LDAP)]
        public static extern int ldap_msgfree(
            IntPtr msg);

        [DllImport(LIB_LDAP)]
        public static extern SafeLdapMemory ldap_next_attribute(
            SafeLdapHandle ld,
            IntPtr entry,
            SafeBerElement ber);

        [DllImport(LIB_LDAP)]
        public static extern IntPtr ldap_next_entry(
            SafeLdapHandle ldap,
            IntPtr entry);

        [DllImport(LIB_LDAP)]
        public static extern int ldap_parse_result(
            SafeLdapHandle ld,
            IntPtr result,
            out int errcodep,
            out SafeLdapMemory matcheddnp,
            out SafeLdapMemory errmsgp,
            out SafeLdapMemoryArray referralsp,
            out SafeLdapControls serverctrlsp,
            int freeid);

        [DllImport(LIB_LDAP)]
        public static extern int ldap_result(
            SafeLdapHandle ld,
            int msgid,
            LDAPMessageCount all,
            SafeHandle timeout,
            out SafeLdapMessage result);

        [DllImport(LIB_LDAP)]
        public static extern int ldap_sasl_bind(
            SafeLdapHandle ld,
            string dn,
            string? mechanism,
            SafeHandle cred,
            SafeHandle sctrls,
            SafeHandle cctrls,
            out int msgidp);

        [DllImport(LIB_LDAP)]
        public static extern int ldap_sasl_interactive_bind(
            SafeLdapHandle ld,
            string dn,
            string mechs,
            SafeHandle sctrls,
            SafeHandle cctrls,
            SASLInteractionFlags flags,
            [MarshalAs(UnmanagedType.FunctionPtr)] LDAP_SASL_INTERACT_PROC interact,
            IntPtr defaults,
            SafeHandle result,
            ref IntPtr rmechp,
            out int msgidp);

        [DllImport(LIB_LDAP)]
        public static extern int ldap_search_ext(
            SafeLdapHandle ld,
            string searchbase,
            LDAPSearchScope scope,
            string? filter,
            SafeHandle attrs,
            int attrsonly,
            SafeHandle serverctrls,
            SafeHandle clientctrls,
            SafeHandle timeout,
            int sizelimit,
            out int msgidp);

        [DllImport(LIB_LDAP)]
        public static extern int ldap_set_option(
            SafeLdapHandle ld,
            LDAPOption option,
            [In] ref int invalue);

        [DllImport(LIB_LDAP)]
        public static extern int ldap_set_option(
            SafeLdapHandle ld,
            LDAPOption option,
            IntPtr invalue);

        [DllImport(LIB_LDAP)]
        public static extern int ldap_start_tls_s(
            SafeLdapHandle ld,
            SafeHandle serverctrls,
            SafeHandle clientctrls);

        [DllImport(LIB_LDAP)]
        public static extern int ldap_unbind(
            IntPtr ld);

        [DllImport(LIB_LDAP)]
        public static extern void ldap_value_free_len(
            IntPtr vals);

        /// <summary>Get a short description for the error code provided.</summary>
        /// <param name="error">The error code to convert to a string.</param>
        /// <see href="https://www.openldap.org/software/man.cgi?query=ldap_err2string&amp;apropos=0&amp;sektion=3&amp;manpath=OpenLDAP+2.6-Release&amp;arch=default&amp;format=html">ldap_err2string</see>
        public static string Err2String(int error)
        {
            return Marshal.PtrToStringUTF8(ldap_err2string(error)) ?? "";
        }

        /// <summary>Get the attribute names of an LDAP entry.</summary>
        /// <param name="ldap">The LDAP handle the entry is associated with.</param>
        /// <param name="entry">The entry pointer to get the attributes of.</param>
        /// <returns>Yields the attribute names of the entry.</returns>
        /// <exception cref="LDAPException">A general LDAP failure occurred when getting the attribute names.</exception>
        /// <see href="https://www.openldap.org/software/man.cgi?query=ldap_first_attribute&amp;sektion=3&amp;apropos=0&amp;manpath=OpenLDAP+2.6-Release">ldap_first_attribute</see>
        public static IEnumerable<string> GetAttributes(SafeLdapHandle ldap, IntPtr entry)
        {
            using SafeLdapMemory res = ldap_first_attribute(ldap, entry, out var element);
            if (res.IsInvalid)
            {
                int rc = GetOptionInt(ldap, LDAPOption.LDAP_OPT_RESULT_CODE);
                if (rc != 0)
                    throw new LDAPException(ldap, rc, "ldap_first_attribute");

                yield break;
            }

            using (element)
            {
                yield return Marshal.PtrToStringUTF8(res.DangerousGetHandle()) ?? "";

                while (true)
                {
                    using SafeLdapMemory attribute = ldap_next_attribute(ldap, entry, element);
                    if (attribute.IsInvalid)
                        break;

                    yield return Marshal.PtrToStringUTF8(attribute.DangerousGetHandle()) ?? "";
                }
            }
        }

        /// <summary>Get the entry pointers in an LDAP result buffer.</summary>
        /// <param name="ldap">The LDAP handle the entry is associated with.</param>
        /// <param name="result">The result set to get the first entry for.</param>
        /// <returns>Yields the entry pointers of the result buffer.</returns>
        /// <exception cref="LDAPException">A general LDAP failure occurred when getting the entries.</exception>
        /// <see href="https://www.openldap.org/software/man.cgi?query=ldap_first_entry&amp;sektion=3&amp;apropos=0&amp;manpath=OpenLDAP+2.6-Release">ldap_first_entry</see>
        public static IEnumerable<IntPtr> GetEntries(SafeLdapHandle ldap, SafeLdapMessage result)
        {
            IntPtr entry = ldap_first_entry(ldap, result);
            if (entry == IntPtr.Zero)
            {
                (int rc, string _, string errMsg) = ParseResult(ldap, result);
                if (rc != 0)
                    throw new LDAPException(ldap, rc, "ldap_first_entry", errorMessage: errMsg);

                yield break;
            }

            while (true)
            {
                yield return entry;
                entry = ldap_next_entry(ldap, entry);

                if (entry == IntPtr.Zero)
                {
                    (int rc, string _, string errMsg) = ParseResult(ldap, result);
                    if (rc != 0)
                        throw new LDAPException(ldap, rc, "ldap_next_entry", errorMessage: errMsg);

                    yield break;
                }

                yield return entry;
            }
        }

        /// <summary>Get an integer option value from an LDAP connection or globally.</summary>
        /// <param name="ldap">The LDAP connection or null for a global option.</param>
        /// <param name="option">The LDAP option to get.</param>
        /// <returns>The option value as an integer.</returns>
        /// <exception cref="LDAPException">A general LDAP failure occurred when getting the option.</exception>
        /// <see href="https://www.openldap.org/software/man.cgi?query=ldap_set_option&amp;apropos=0&amp;sektion=0&amp;manpath=OpenLDAP+2.6-Release&amp;arch=default&amp;format=html">ldap_get_option</see>
        public static int GetOptionInt(SafeLdapHandle ldap, LDAPOption option)
        {
            int res = ldap_get_option(ldap, option, out int value);
            if (res != 0)
                throw new LDAPException(ldap, res, $"ldap_get_option({option})");

            return value;
        }

        /// <summary>Get a string option value from an LDAP connection or globally.</summary>
        /// <param name="ldap">The LDAP connection or null for a global option.</param>
        /// <param name="option">The LDAP option to get.</param>
        /// <returns>The option value as a string.</returns>
        /// <exception cref="LDAPException">A general LDAP failure occurred when getting the option.</exception>
        /// <see href="https://www.openldap.org/software/man.cgi?query=ldap_set_option&amp;apropos=0&amp;sektion=0&amp;manpath=OpenLDAP+2.6-Release&amp;arch=default&amp;format=html">ldap_get_option</see>
        public static string GetOptionString(SafeLdapHandle ldap, LDAPOption option)
        {
            int res = ldap_get_option(ldap, option, out SafeLdapMemory value);
            if (res != 0)
                throw new LDAPException(ldap, res, $"ldap_get_option({option})");

            return Marshal.PtrToStringUTF8(value.DangerousGetHandle()) ?? "";
        }

        /// <summary>Get the list of available SASL mechs.</summary>
        /// <param name="ldap">The LDAP connection or null for a global option.</param>
        /// <returns>The list of available SASL mechanisms.</returns>
        /// <exception cref="LDAPException">A general LDAP failure occurred when getting the option.</exception>
        /// <see href="https://www.openldap.org/software/man.cgi?query=ldap_set_option&amp;apropos=0&amp;sektion=0&amp;manpath=OpenLDAP+2.6-Release&amp;arch=default&amp;format=html">ldap_get_option</see>
        public static List<string> GetOptionSaslMechList(SafeLdapHandle? ldap)
        {
            const LDAPOption option = LDAPOption.LDAP_OPT_X_SASL_MECHLIST;
            int res = ldap_get_option(ldap ?? new SafeLdapHandle(), option, out IntPtr value);
            if (res != 0)
                throw new LDAPException(ldap, res, $"ldap_get_option({option})");

            // The return value for this is special which is why it has it's own function.
            List<string> mechs = new List<string>();
            while (true)
            {
                string? mech = Marshal.PtrToStringUTF8(Marshal.ReadIntPtr(value));
                if (String.IsNullOrEmpty(mech))
                    break;

                mechs.Add(mech);
                value = IntPtr.Add(value, IntPtr.Size);
            }

            return mechs;
        }

        /// <summary>Get values for an entry attribute.</summary>
        /// <param name="ldap">The LDAP handle the entry and attribute are associated with.</param>
        /// <param name="entry">The entry pointer to get the attribute values of.</param>
        /// <param name="attr">The name of the attribute to get the values for.</param>
        /// <returns>Yields the raw byte[] values of the attribute.</returns>
        /// <exception cref="LDAPException">A general LDAP failure occurred when trying to parse the attributes values.</exception>
        /// <see href="https://www.openldap.org/software/man.cgi?query=ldap_get_values&amp;apropos=0&amp;sektion=3&amp;manpath=OpenLDAP+2.6-Release&amp;arch=default&amp;format=html">ldap_get_values_len</see>
        public static IEnumerable<byte[]> GetValues(SafeLdapHandle ldap, IntPtr entry, string attr)
        {
            using SafeLdapValueArray raw = ldap_get_values_len(ldap, entry, attr);
            if (raw.IsInvalid)
            {
                int rc = GetOptionInt(ldap, LDAPOption.LDAP_OPT_RESULT_CODE);
                throw new LDAPException(ldap, rc, "ldap_get_values_len");
            }

            int count = ldap_count_values_len(raw);
            List<byte[]> values = new List<byte[]>(count);
            unsafe
            {
                foreach (IntPtr ptr in new Span<IntPtr>(raw.DangerousGetHandle().ToPointer(), count))
                {
                    Helpers.berval* v = (Helpers.berval*)ptr.ToPointer();

                    byte[] data = new byte[v->bv_len];
                    Marshal.Copy(v->bv_val, data, 0, data.Length);
                    values.Add(data);
                }
            }

            return values.ToArray();
        }

        /// <summary>Initializes an LDAP handle for the URI specified.</summary>
        /// <remarks>
        /// This will not start the connection to the endpoint but builds the internal structure that stores the LDAP connection and connection details.
        /// </remarks>
        /// <param name="uri">The LDAP URI to initialize the connection on.</param>
        /// <returns>The handle to the LDAP connection all subsequent operations should be run on.</returns>
        /// <exception cref="LDAPException">A general LDAP failure occurred when trying to initialize the handle.</exception>
        /// <see href="https://www.openldap.org/software/man.cgi?query=ldap_initialize&amp;apropos=0&amp;sektion=3&amp;manpath=OpenLDAP+2.6-Release&amp;arch=default&amp;format=html">ldap_initialize</see>
        public static SafeLdapHandle Initialize(string uri)
        {
            int err = ldap_initialize(out var ldap, uri);
            if (err != 0)
                throw new LDAPException(null, err, "ldap_initialize");

            return ldap;
        }

        /// <summary>Parse LDAP result information.</summary>
        /// <param name="ldap">The LDAP handle the result is associated with.</param>
        /// <param name="ldap">The result from <C>Result</C> to parse.</param>
        /// <returns>
        /// A tuple of 3 values:
        ///   1 - The error code in the LDAP result.
        ///   2 - How much of the name in the request was recongnized.
        ///   3 - Error message from the LDAP result.
        /// </returns>
        /// <exception cref="LDAPException">A general LDAP failure occurred when trying to parse the results.</exception>
        /// <see href="https://www.openldap.org/software/man.cgi?query=ldap_parse_result&amp;apropos=0&amp;sektion=0&amp;manpath=OpenLDAP+2.6-Release&amp;arch=default&amp;format=html">ldap_parse_result</see>
        public static (int, string, string) ParseResult(SafeLdapHandle ldap, SafeLdapMessage result)
        {
            int rc = ldap_parse_result(ldap, result.DangerousGetHandle(), out var errorCode, out var matchedDNBuffer,
                out var errMsgBuffer, out var referralBuffer, out var serverControl, 0);
            if (rc != 0)
                throw new LDAPException(ldap, rc, "ldap_parse_result");

            using (matchedDNBuffer)
            using (errMsgBuffer)
            using (referralBuffer)
            using (serverControl)
            {
                string matchedDN = Marshal.PtrToStringUTF8(matchedDNBuffer.DangerousGetHandle()) ?? "";
                string errMsg = Marshal.PtrToStringUTF8(errMsgBuffer.DangerousGetHandle()) ?? "";

                return (errorCode, matchedDN, errMsg);
            }
        }

        /// <summary>Wait for the result of an LDAP operation.</summary>
        /// <param name="ldap">The connected LDAP handle.</param>
        /// <param name="messageId">Get the result of the specific message operation. 0 will wait for any and -1 will wait for unsolicted responses.</param>
        /// <param name="waitBehaviour">
        /// Specifies how many messages to wait for.
        /// Set <c>LDAP_MSG_ONE</C> to retrieve one message at a time.
        /// Set <c>LDAP_MSG_ALL</C> to retrieve all messages for the operation.
        /// Set <c>LDAP_MSG_RECEIVED</C> to retrieve all messages that have been received so far for the operation.
        /// </param>
        /// <param name="timeoutMS">
        /// The timeout in milliseconds to wait for.
        /// Set to 0 to use the connection timeout default.
        /// Set to -1 to wait indefinitely.
        /// </param>
        /// <returns>The unmanaged memory containing the search results.</returns>
        /// <exception cref="LDAPException">A general LDAP failure occurred when getting the result.</exception>
        /// <exception cref="TimeoutException">Timed out waiting for a result.</exception>
        /// <see href="https://www.openldap.org/software/man.cgi?query=ldap_result&amp;sektion=3&amp;apropos=0&amp;manpath=OpenLDAP+2.6-Release">ldap_result</see>
        public static SafeLdapMessage Result(SafeLdapHandle ldap, int messageId, LDAPMessageCount waitBehaviour, int timeoutMS = 0)
        {
            using SafeMemoryBuffer timeout = TimeoutBuffer(timeoutMS);
            int rc = ldap_result(ldap, messageId, waitBehaviour, timeout, out var result);
            if (rc == 0)
            {
                throw new TimeoutException();
            }
            else if (rc == -1)
            {
                rc = GetOptionInt(ldap, LDAPOption.LDAP_OPT_RESULT_CODE);
                throw new LDAPException(ldap, rc, "ldap_result");
            }

            result.ResultType = (LDAPResultType)rc;
            return result;
        }

        /// <summary>Asynchronously starts a low-level SASL bind operation on the LDAP connection specified.</summary>
        /// <remarks>
        /// This is a lower level operation compared to <C>SaslInteractiveBind</C> that is used to exchange the
        /// credential tokens directory rather than through OpenLDAP calling the SASL mechanism itself. It is also
        /// used to provide SIMPLE authentication when <paramref name="mechanism"/> is null.
        /// This is an asynchronous operation and <C>Result</C> should be called to wait for a response and validate
        /// whether the bind was successful or not.
        /// The value of <paramref name="dn"/> is dependent on the mechanism used. Typically this is the DN of the
        /// username but could be another form.
        /// The value of <paramref name="cred"/> is dependent on the mechanism used. For SIMPLE auth this is the
        /// password encoded as bytes.
        /// </remarks>
        /// <param name="ldap">The LDAP handle to perform the bind on.</param>
        /// <param name="dn">Who/username to bind with.</param>
        /// <param name="mechanism">The SASL mechanism used or null for SIMPLE auth.</param>
        /// <param name="cred">The raw credential to exchange.</param>
        /// <param name="serverControls">Optional LDAP control codes to be sent to the server for the request.</param>
        /// <param name="clientControls">Optional LDAP control codes to be used by the client for the request.</param>
        /// <returns>The message identifier for the bind request.</returns>
        /// <exception cref="LDAPException">A general LDAP failure occurred when starting the bind operation.</exception>
        /// <see href="https://www.openldap.org/software/man.cgi?query=ldap_sasl_bind&amp;apropos=0&amp;sektion=0&amp;manpath=OpenLDAP+2.6-Release&amp;arch=default&amp;format=html">ldap_sasl_bind</see>
        public static int SaslBind(SafeLdapHandle ldap, string dn, string? mechanism, byte[] cred,
            LDAPControl[]? serverControls = null, LDAPControl[]? clientControls = null)
        {
            int credStructLength = Marshal.SizeOf<Helpers.berval>();
            using SafeMemoryBuffer credBuffer = new SafeMemoryBuffer(credStructLength + cred.Length);
            Helpers.berval credStruct = new Helpers.berval()
            {
                bv_len = cred.Length,
                bv_val = IntPtr.Add(credBuffer.DangerousGetHandle(), credStructLength),
            };
            Marshal.Copy(cred, 0, credStruct.bv_val, cred.Length);
            Marshal.StructureToPtr(credStruct, credBuffer.DangerousGetHandle(), false);

            using SafeMemoryBuffer serverCC = ControlCodeBuffer(serverControls);
            using SafeMemoryBuffer clientCC = ControlCodeBuffer(clientControls);
            int rc = ldap_sasl_bind(ldap, dn, mechanism, credBuffer, serverCC, clientCC, out var msgid);

            if (rc != 0)
                throw new LDAPException(ldap, rc, "ldap_sasl_bind");

            return msgid;
        }

        /// <summary>Asynchronously starts a SASL bind operation on the LDAP connection specified.</summary>
        /// <remarks>
        /// Depending on the SASL mechanism used there may be multiple roundtrips needed to complete the bind
        /// operation. If the return value[0] is true then <C>Result</C> should be called with the message id
        /// returned by value[1]. The result from <C>Result</C> should then be passed by in to this method as
        /// <paramref name="result"/>. Repeat this until value[0] is false.
        /// A lot of the underlying behaviour of this function is defined by the SASL mechanism called. The interaction
        /// flags and prompt delegate behaviour varies from mechanism to mechanism. For GSSAPI and GSS-SPNEGO the
        /// prompt is always called and the interaction flags define whether data is printed to the console or not. It
        /// is recommended to use <C>LDAP_SASL_QUIET</C> to avoid the console output pollution for these mechanisms.
        /// </remarks>
        /// <param name="ldap">The LDAP handle to perform the bind on.</param>
        /// <param name="dn">Not used with SASL and should be an empty string.</param>
        /// <param name="mech">The SASL mechanism identifiers delimited by spaces.</param>
        /// <param name="interactionFlags">
        /// Interaction used to retrieve any necessary SASL authentication parameters.
        /// Set <c>LDAP_SASL_AUTOMATIC</C> to use defaults if available.
        /// Set <c>LDAP_SASL_INTERACTIVE</C> to always prompt.
        /// Set <c>LDAP_SASL_QUIET</C> to never prompt.
        /// </param>
        /// <param name="prompt">The callback used by the SASL mechanism when prompting for further information.</param>
        /// <param name="result">The input result data for SASL to process from a <C>Result</C> or null for the first invocation.</param>
        /// <param name="rmech">A reference IntPtr that contains the current SASL mech being used. This must be the same value across multiple called.</param>
        /// <param name="serverControls">Optional LDAP control codes to be sent to the server for the request.</param>
        /// <param name="clientControls">Optional LDAP control codes to be used by the client for the request.</param>
        /// <returns>
        /// A tuple of 2 values:
        ///   1 - Whether more processing is required with <C>Result</C>.
        ///   2 - The message identifier to use when processing the result.
        /// </returns>
        /// <exception cref="LDAPException">A general LDAP failure occurred when starting the SASL bind operation.</exception>
        /// <see href="https://www.openldap.org/software/man.cgi?query=ldap_sasl_bind&amp;apropos=0&amp;sektion=0&amp;manpath=OpenLDAP+2.6-Release&amp;arch=default&amp;format=html">ldap_sasl_interactive_bind</see>
        public static (bool, int) SaslInteractiveBind(SafeLdapHandle ldap, string dn, string mech,
            SASLInteractionFlags interactionFlags, SaslInteract prompt, SafeLdapMessage result, ref IntPtr rmech,
            LDAPControl[]? serverControls = null, LDAPControl[]? clientControls = null)
        {
            using SafeMemoryBuffer serverCC = ControlCodeBuffer(serverControls);
            using SafeMemoryBuffer clientCC = ControlCodeBuffer(clientControls);
            int rc = ldap_sasl_interactive_bind(ldap, dn, mech, serverCC, clientCC, interactionFlags,
                prompt.SaslInteractProc, IntPtr.Zero, result, ref rmech, out var msgid);
            // While the caller may have this in a using block it doesn't hurt to call it more than once.
            result.Dispose();

            bool moreProcessingRequired = false;
            if (rc == (int)LDAPResultCode.LDAP_SASL_BIND_IN_PROGRESS)
                moreProcessingRequired = true;
            else if (rc != 0)
                throw new LDAPException(ldap, rc, "ldap_sasl_interactive_bind");

            return (moreProcessingRequired, msgid);
        }

        /// <summary>Start an asynchrnous search option.</summary>
        /// <remarks>
        /// This function runs asynchronously and the returned message identifier is used by <C>Result</C> to wait for
        /// a result from the server.
        /// </remarks>
        /// <param name="ldap">The LDAP connection to perform the search on.</param>
        /// <param name="searchBase">The DN of the entry at which to start the search.</param>
        /// <param name="scope">
        /// The scope of the search as one of the following values.
        /// Set <c>LDAP_SCOPE_BASE</C> to search against the entry specified by the search base.
        /// Set <c>LDAP_SCOPE_ONELEVEL</C> to search entries that are immediate subordinates of the search base.
        /// Set <c>LDAP_SCOPE_SUBTREE</C> to search entries that are subordinates and their subordinates of the search base.
        /// Set <c>LDAP_SCOPE_SUBORDINATE</C> like <C>LDAP_SCOPE_SUBTREE</C> but it does not include the entry of search base itself.
        /// </param>
        /// <param name="filter">The LDAP search filter to apply or null to send <C>(objectClass=*)</C>.</param>
        /// <param name="attributes">
        /// A list of attributes to retrieve for each matching entry.
        /// If null or <C>*</C> is specified then all user attributes are returned.
        /// If <C>+</C> is specified then all operational attributes are returned.
        /// If <C>1.1</C> is specified then no attributes then no attributes are returned.
        /// </param>
        /// <param name="attributesOnly">Request only the attribute names and not their values.</param>
        /// <param name="timeoutMS">
        /// The operational timeout used by the server when gathering the query data.
        /// A value of 0 will use the server defined operation timeout value.
        /// </param>
        /// <param name="sizeLimit">The number of entries to return with 0 indicating no limits.</param>
        /// <param name="serverControls">Optional LDAP control codes to be sent to the server for the request.</param>
        /// <param name="clientControls">Optional LDAP control codes to be used by the client for the request.</param>
        /// <returns>The search message id to be used with <C>Result</C></returns>
        /// <exception cref="LDAPException">A general LDAP failure occurred when getting the result.</exception>
        /// <see href="https://www.openldap.org/software/man.cgi?query=ldap_search_ext&amp;apropos=0&amp;sektion=0&amp;manpath=OpenLDAP+2.6-Release&amp;arch=default&amp;format=html">ldap_search_ext</see>
        public static int SearchExt(SafeLdapHandle ldap, string searchBase, LDAPSearchScope scope, string? filter,
            string[]? attributes, bool attributesOnly, int timeoutMS = 0, int sizeLimit = 0,
            LDAPControl[]? serverControls = null, LDAPControl[]? clientControls = null)
        {
            SafeMemoryBuffer attributesBuffer;
            int attributesLength = IntPtr.Size; // Include null pointer at the end of the pointer array
            List<byte[]> attributeBytes = new List<byte[]>();
            if (attributes == null)
            {
                attributesBuffer = new SafeMemoryBuffer();
            }
            else
            {
                foreach (string attr in attributes)
                {
                    byte[] attrData = Encoding.UTF8.GetBytes(attr + '\0');
                    attributesLength += attrData.Length;
                    attributeBytes.Add(attrData);
                }

                attributesBuffer = new SafeMemoryBuffer((IntPtr.Size * attributeBytes.Count) + attributesLength);
            }

            using (attributesBuffer)
            {
                if (attributeBytes.Count > 0)
                {
                    IntPtr pointerPtr = attributesBuffer.DangerousGetHandle();
                    IntPtr valuePtr = IntPtr.Add(pointerPtr, (IntPtr.Size * attributeBytes.Count) + IntPtr.Size);
                    foreach (byte[] attr in attributeBytes)
                    {
                        Marshal.WriteIntPtr(pointerPtr, valuePtr);
                        Marshal.Copy(attr, 0, valuePtr, attr.Length);
                        pointerPtr = IntPtr.Add(pointerPtr, IntPtr.Size);
                        valuePtr = IntPtr.Add(valuePtr, attr.Length);
                    }
                    Marshal.WriteIntPtr(pointerPtr, IntPtr.Zero);
                }

                using SafeMemoryBuffer serverCC = ControlCodeBuffer(serverControls);
                using SafeMemoryBuffer clientCC = ControlCodeBuffer(clientControls);
                using SafeMemoryBuffer timeout = TimeoutBuffer(timeoutMS);
                int rc = ldap_search_ext(ldap, searchBase, scope, filter, attributesBuffer, attributesOnly ? 1 : 0,
                    serverCC, clientCC, timeout, sizeLimit, out var msgid);
                if (rc != 0)
                    throw new LDAPException(ldap, rc, "ldap_search_ext");

                return msgid;
            }
        }

        /// <summary>Sets an integer based LDAP option either globally or on a connection.</summary>
        /// <param name="ldap">The LDAP connection or null to set globally.</param>
        /// <param name="option">The LDAP option to set.</param>
        /// <param name="value">The option value as an integer.</param>
        /// <exception cref="LDAPException">A general LDAP failure occurred when setting the option.</exception>
        /// <see href="https://www.openldap.org/software/man.cgi?query=ldap_set_option&amp;apropos=0&amp;sektion=0&amp;manpath=OpenLDAP+2.6-Release&amp;arch=default&amp;format=html">ldap_set_option</see>
        public static void SetOption(SafeLdapHandle? ldap, LDAPOption option, int value)
        {
            int res = ldap_set_option(ldap ?? new SafeLdapHandle(), option, ref value);
            if (res != 0)
                throw new LDAPException(ldap, res, $"ldap_set_option({option})");
        }

        /// <summary>Set a raw pointer based LDAP option either globally or on a connection.</summary>
        /// <param name="ldap">The LDAP connection or null to set globally.</param>
        /// <param name="option">The LDAP option to set.</param>
        /// <param name="value">The option value as an integer.</param>
        /// <exception cref="LDAPException">A general LDAP failure occurred when setting the option.</exception>
        /// <see href="https://www.openldap.org/software/man.cgi?query=ldap_set_option&amp;apropos=0&amp;sektion=0&amp;manpath=OpenLDAP+2.6-Release&amp;arch=default&amp;format=html">ldap_set_option</see>
        public static void SetOption(SafeLdapHandle? ldap, LDAPOption option, IntPtr value)
        {
            int res = ldap_set_option(ldap ?? new SafeLdapHandle(), option, value);
            if (res != 0)
                throw new LDAPException(ldap, res, $"ldap_set_option({option})");
        }

        /// <summary>Initiate a StartTLS bind on the LDAP connection.</summary>
        /// <param name="ldap">The LDAP handle to perform the StartTLS operation on.</param>
        /// <param name="serverControls">Optional LDAP control codes to be sent to the server for the request.</param>
        /// <param name="clientControls">Optional LDAP control codes to be used by the client for the request.</param>
        /// <exception cref="LDAPException">A general LDAP failure occurred when performing the StartTLS operation.</exception>
        /// <see href="https://www.openldap.org/software/man.cgi?query=ldap_start_tls_s&amp;apropos=0&amp;sektion=0&amp;manpath=OpenLDAP+2.6-Release&amp;arch=default&amp;format=html">ldap_start_tls_s</see>
        public static void StartTlsS(SafeLdapHandle ldap, LDAPControl[]? serverControls = null,
            LDAPControl[]? clientControls = null)
        {
            using SafeMemoryBuffer serverCC = ControlCodeBuffer(serverControls);
            using SafeMemoryBuffer clientCC = ControlCodeBuffer(clientControls);
            int res = ldap_start_tls_s(ldap, serverCC, clientCC);
            if (res != 0)
                throw new LDAPException(ldap, res, "ldap_start_tls_ts");
        }

        private static SafeMemoryBuffer ControlCodeBuffer(LDAPControl[]? codes)
        {
            if (!(codes?.Length > 0))
                return new SafeMemoryBuffer();

            int pointerSize = IntPtr.Size + (IntPtr.Size * codes.Length);
            //int pointerSize = IntPtr.Size;
            int structSize = Marshal.SizeOf<Helpers.LDAPControl>() * codes.Length;
            int oidSize = 0;
            int valueSize = 0;
            List<byte[]> oidBytes = new List<byte[]>(codes.Length);

            foreach (LDAPControl code in codes)
            {
                byte[] oid = Encoding.UTF8.GetBytes(code.Oid + '\0');
                oidSize += oid.Length;
                oidBytes.Add(oid);
                valueSize += code.Value?.Length ?? 0;
            }

            SafeMemoryBuffer buffer = new SafeMemoryBuffer(pointerSize + structSize + oidSize + valueSize);
            try
            {
                IntPtr structPtr = IntPtr.Add(buffer.DangerousGetHandle(), pointerSize);
                //IntPtr structPtr = IntPtr.Add(buffer.DangerousGetHandle(), 0);
                IntPtr oidPtr = IntPtr.Add(structPtr, structSize);
                //IntPtr oidPtr = IntPtr.Add(structPtr, IntPtr.Size + structSize);
                IntPtr valuePtr = IntPtr.Add(oidPtr, oidSize);

                for (int i = 0; i < codes.Length; i++)
                {
                    LDAPControl code = codes[i];

                    Helpers.LDAPControl control = new Helpers.LDAPControl()
                    {
                        ldctl_oid = oidPtr,
                        ldctl_value = new Helpers.berval()
                        {
                            bv_len = 0,
                            bv_val = IntPtr.Zero,
                        },
                        ldctl_iscritical = code.IsCritical,
                    };

                    byte[] oid = oidBytes[i];
                    Marshal.Copy(oid, 0, oidPtr, oid.Length);
                    oidPtr = IntPtr.Add(oidPtr, oid.Length);

                    if (code.Value?.Length > 0)
                    {
                        control.ldctl_value.bv_len = code.Value.Length;
                        control.ldctl_value.bv_val = valuePtr;
                        Marshal.Copy(code.Value, 0, valuePtr, code.Value.Length);
                        valuePtr = IntPtr.Add(valuePtr, code.Value.Length);
                    }

                    Marshal.StructureToPtr(control, structPtr, false);
                    Marshal.WriteIntPtr(buffer.DangerousGetHandle(), i * IntPtr.Size, structPtr);
                    structPtr = IntPtr.Add(structPtr, Marshal.SizeOf<Helpers.LDAPControl>());
                }
                Marshal.WriteIntPtr(buffer.DangerousGetHandle(), pointerSize - IntPtr.Size, IntPtr.Zero);

                return buffer;
            }
            catch
            {
                buffer.Dispose();
                throw;
            }
        }

        private static SafeMemoryBuffer TimeoutBuffer(int timeoutMS)
        {
            if (timeoutMS == 0)
                return new SafeMemoryBuffer();
            else if (timeoutMS == -1)
                timeoutMS = -1000;

            Helpers.timeval timeout = new Helpers.timeval()
            {
                tv_sec = (int)Math.Floor((double)timeoutMS / 1000),
                tv_usec = timeoutMS % 1000,
            };

            SafeMemoryBuffer buffer = new SafeMemoryBuffer(Marshal.SizeOf<Helpers.timeval>());
            try
            {
                Marshal.StructureToPtr(timeout, buffer.DangerousGetHandle(), false);
            }
            catch
            {
                buffer.Dispose();
                throw;
            }

            return buffer;
        }
    }

    public class LDAPException : Exception
    {
        public int ErrorCode { get; }

        public string? ErrorMessage { get; }

        internal LDAPException(SafeLdapHandle? ldap, int error)
            : base(GetExceptionMessage(ldap, error, null, null)) => ErrorCode = error;

        internal LDAPException(SafeLdapHandle? ldap, int error, string method, string? errorMessage = null)
            : base(GetExceptionMessage(ldap, error, method, errorMessage))
        {
            ErrorCode = error;
            ErrorMessage = errorMessage;
        }

        private static string GetExceptionMessage(SafeLdapHandle? ldap, int error, string? method,
             string? errorMessage)
        {
            method = String.IsNullOrWhiteSpace(method) ? "LDAP Call" : method;
            string errString = OpenLDAP.Err2String(error);
            if (String.IsNullOrWhiteSpace(errorMessage) && ldap?.IsInvalid == false && ldap?.IsClosed == false)
                errorMessage = OpenLDAP.GetOptionString(ldap, LDAPOption.LDAP_OPT_DIAGNOSTIC_MESSAGE);

            string msg = $"{method} failed ({error} - {errString})";
            if (!String.IsNullOrWhiteSpace(errorMessage))
                msg += $" - {errorMessage}";

            return msg;
        }
    }

    internal class SafeBerElement : SafeHandle
    {
        internal SafeBerElement() : base(IntPtr.Zero, true) { }

        public override bool IsInvalid => handle == IntPtr.Zero;

        protected override bool ReleaseHandle()
        {
            OpenLDAP.ber_free(handle, 0);
            return true;
        }
    }

    internal class SafeLdapHandle : SafeHandle
    {
        internal SafeLdapHandle() : base(IntPtr.Zero, true) { }

        public override bool IsInvalid => handle == IntPtr.Zero;

        protected override bool ReleaseHandle()
        {
            return OpenLDAP.ldap_unbind(handle) == 0;
        }
    }

    internal class SafeLdapMessage : SafeHandle
    {
        public LDAPResultType ResultType { get; set; } = LDAPResultType.LDAP_RES_UNKNOWN;

        internal SafeLdapMessage() : base(IntPtr.Zero, true) { }

        public override bool IsInvalid => handle == IntPtr.Zero;

        protected override bool ReleaseHandle()
        {
            return OpenLDAP.ldap_msgfree(handle) == 0;
        }
    }

    internal class SafeLdapMemory : SafeHandle
    {
        internal SafeLdapMemory() : base(IntPtr.Zero, true) { }

        public override bool IsInvalid => handle == IntPtr.Zero;

        protected override bool ReleaseHandle()
        {
            OpenLDAP.ldap_memfree(handle);
            return true;
        }
    }

    internal class SafeLdapMemoryArray : SafeHandle
    {
        internal SafeLdapMemoryArray() : base(IntPtr.Zero, true) { }

        public override bool IsInvalid => handle == IntPtr.Zero;

        protected override bool ReleaseHandle()
        {
            OpenLDAP.ldap_memvfree(handle);
            return true;
        }
    }

    internal class SafeLdapControls : SafeHandle
    {
        internal SafeLdapControls() : base(IntPtr.Zero, true) { }

        public override bool IsInvalid => handle == IntPtr.Zero;

        protected override bool ReleaseHandle()
        {
            OpenLDAP.ldap_controls_free(handle);
            return true;
        }
    }

    internal class SafeLdapValueArray : SafeHandle
    {
        internal SafeLdapValueArray() : base(IntPtr.Zero, true) { }

        public override bool IsInvalid => handle == IntPtr.Zero;

        protected override bool ReleaseHandle()
        {
            OpenLDAP.ldap_value_free_len(handle);
            return true;
        }
    }

    internal class SafeMemoryBuffer : SafeHandle
    {
        public int Length { get; } = 0;

        internal SafeMemoryBuffer() : base(IntPtr.Zero, true) { }

        internal SafeMemoryBuffer(int size) : base(Marshal.AllocHGlobal(size), true) => Length = size;

        internal SafeMemoryBuffer(string value) : base(IntPtr.Zero, true)
        {
            byte[] data = Encoding.UTF8.GetBytes(value);
            Length = data.Length;

            handle = Marshal.AllocHGlobal(Length);
            Marshal.Copy(data, 0, handle, Length);
        }

        internal SafeMemoryBuffer(IntPtr buffer, bool ownsHandle) : base(buffer, ownsHandle) { }

        public override bool IsInvalid => handle == IntPtr.Zero;

        protected override bool ReleaseHandle()
        {
            Marshal.FreeHGlobal(handle);
            return true;
        }
    }

    internal enum LDAPChannelBinding
    {
        LDAP_OPT_X_SASL_CBINDING_NONE = 0,
        LDAP_OPT_X_SASL_CBINDING_TLS_UNIQUE = 1,
        LDAP_OPT_X_SASL_CBINDING_TLS_ENDPOINT = 2,
    }

    internal enum LDAPResultType
    {
        LDAP_RES_UNKNOWN = 0x00,
        LDAP_RES_BIND = 0x61,
        LDAP_RES_SEARCH_ENTRY = 0x64,
        LDAP_RES_SEARCH_RESULT = 0x65,
        LDAP_RES_MODIFY = 0x67,
        LDAP_RES_ADD = 0x69,
        LDAP_RES_DELETE = 0x6b,
        LDAP_RES_MODDN = 0x6d,
        LDAP_RES_COMPARE = 0x6f,
        LDAP_RES_SEARCH_REFERENCE = 0x73,
        LDAP_RES_EXTENDED = 0x78,
        LDAP_RES_INTERMEDIATE = 0x79,
    }

    public enum LDAPResultCode
    {
        LDAP_SASL_BIND_IN_PROGRESS = 14,
    }

    internal enum LDAPMessageCount
    {
        LDAP_MSG_ONE = 0x00,
        LDAP_MSG_ALL = 0x01,
        LDAP_MSG_RECEIVED = 0x02,
    }

    internal enum LDAPOption
    {
        LDAP_OPT_API_INFO = 0x0000,
        LDAP_OPT_DESC = 0x0001,
        LDAP_OPT_DEREF = 0x0002,
        LDAP_OPT_SIZELIMIT = 0x0003,
        LDAP_OPT_TIMELIMIT = 0x0004,
        LDAP_OPT_REFERRALS = 0x0008,
        LDAP_OPT_RESTART = 0x0009,
        LDAP_OPT_PROTOCOL_VERSION = 0x0011,
        LDAP_OPT_SERVER_CONTROLS = 0x0012,
        LDAP_OPT_CLIENT_CONTROLS = 0x0013,
        LDAP_OPT_API_FEATURE_INFO = 0x0015,
        LDAP_OPT_HOST_NAME = 0x0030,
        LDAP_OPT_RESULT_CODE = 0x0031,
        LDAP_OPT_ERROR_NUMBER = LDAP_OPT_RESULT_CODE,
        LDAP_OPT_DIAGNOSTIC_MESSAGE = 0x0032,
        LDAP_OPT_ERROR_STRING = LDAP_OPT_DIAGNOSTIC_MESSAGE,
        LDAP_OPT_MATCHED_DN = 0x0033,
        LDAP_OPT_SSPI_FLAGS = 0x0092,
        LDAP_OPT_SIGN = 0x0095,
        LDAP_OPT_ENCRYPT = 0x0096,
        LDAP_OPT_SASL_METHOD = 0x0097,
        LDAP_OPT_SECURITY_CONTEXT = 0x0099,
        LDAP_OPT_API_EXTENSION_BASE = 0x4000,
        LDAP_OPT_DEBUG_LEVEL = 0x5001,
        LDAP_OPT_TIMEOUT = 0x5002,
        LDAP_OPT_REFHOPLIMIT = 0x5003,
        LDAP_OPT_NETWORK_TIMEOUT = 0x5005,
        LDAP_OPT_URI = 0x5006,
        LDAP_OPT_REFERRAL_URLS = 0x5007,
        LDAP_OPT_SOCKBUF = 0x5008,
        LDAP_OPT_DEFBASE = 0x5009,
        LDAP_OPT_CONNECT_ASYNC = 0x5010,
        LDAP_OPT_CONNECT_CB = 0x5011,
        LDAP_OPT_SESSION_REFCNT = 0x5012,
        LDAP_OPT_KEEPCONN = 0x5013,
        LDAP_OPT_X_TLS = 0x6000,
        LDAP_OPT_X_TLS_CTX = 0x6001,
        LDAP_OPT_X_TLS_CACERTFILE = 0x6002,
        LDAP_OPT_X_TLS_CACERTDIR = 0x6003,
        LDAP_OPT_X_TLS_CERTFILE = 0x6004,
        LDAP_OPT_X_TLS_KEYFILE = 0x6005,
        LDAP_OPT_X_TLS_REQUIRE_CERT = 0x6006,
        LDAP_OPT_X_TLS_PROTOCOL_MIN = 0x6007,
        LDAP_OPT_X_TLS_CIPHER_SUITE = 0x6008,
        LDAP_OPT_X_TLS_RANDOM_FILE = 0x6009,
        LDAP_OPT_X_TLS_SSL_CTX = 0x600a,
        LDAP_OPT_X_TLS_CRLCHECK = 0x600b,
        LDAP_OPT_X_TLS_CONNECT_CB = 0x600c,
        LDAP_OPT_X_TLS_CONNECT_ARG = 0x600d,
        LDAP_OPT_X_TLS_DHFILE = 0x600e,
        LDAP_OPT_X_TLS_NEWCTX = 0x600f,
        LDAP_OPT_X_TLS_CRLFILE = 0x6010,
        LDAP_OPT_X_TLS_PACKAGE = 0x6011,
        LDAP_OPT_X_TLS_ECNAME = 0x6012,
        LDAP_OPT_X_TLS_VERSION = 0x6013,
        LDAP_OPT_X_TLS_CIPHER = 0x6014,
        LDAP_OPT_X_TLS_PEERCERT = 0x6015,
        LDAP_OPT_X_TLS_CACERT = 0x6016,
        LDAP_OPT_X_TLS_CERT = 0x6017,
        LDAP_OPT_X_TLS_KEY = 0x6018,
        LDAP_OPT_X_TLS_PEERKEY_HASH = 0x6019,
        LDAP_OPT_X_TLS_REQUIRE_SAN = 0x601a,
        LDAP_OPT_X_SASL_MECH = 0x6100,
        LDAP_OPT_X_SASL_REALM = 0x6101,
        LDAP_OPT_X_SASL_AUTHCID = 0x6102,
        LDAP_OPT_X_SASL_AUTHZID = 0x6103,
        LDAP_OPT_X_SASL_SSF = 0x6104,
        LDAP_OPT_X_SASL_SSF_EXTERNAL = 0x6105,
        LDAP_OPT_X_SASL_SECPROPS = 0x6106,
        LDAP_OPT_X_SASL_SSF_MIN = 0x6107,
        LDAP_OPT_X_SASL_SSF_MAX = 0x6108,
        LDAP_OPT_X_SASL_MAXBUFSIZE = 0x6109,
        LDAP_OPT_X_SASL_MECHLIST = 0x610a,
        LDAP_OPT_X_SASL_NOCANON = 0x610b,
        LDAP_OPT_X_SASL_USERNAME = 0x610c,
        LDAP_OPT_X_SASL_GSS_CREDS = 0x610d,
        LDAP_OPT_X_SASL_CBINDING = 0x610e,
        LDAP_OPT_X_KEEPALIVE_IDLE = 0x6300,
        LDAP_OPT_X_KEEPALIVE_PROBES = 0x6301,
        LDAP_OPT_X_KEEPALIVE_INTERVAL = 0x6302,
        LDAP_OPT_PRIVATE_EXTENSION_BASE = 0x7000,
    }

    public enum LDAPSearchScope
    {
        LDAP_SCOPE_BASE = 0,
        LDAP_SCOPE_ONELEVEL = 1,
        LDAP_SCOPE_SUBTREE = 2,
        LDAP_SCOPE_SUBORDINATE = 3,
    }

    public enum LDAPTlsSettings
    {
        LDAP_OPT_X_TLS_NEVER = 0,
        LDAP_OPT_X_TLS_HARD = 1,
        LDAP_OPT_X_TLS_DEMAND = 2,
        LDAP_OPT_X_TLS_ALLOW = 3,
        LDAP_OPT_X_TLS_TRY = 4,
    }

    public enum SASLInteractionFlags
    {
        LDAP_SASL_AUTOMATIC = 0,
        LDAP_SASL_INTERACTIVE = 1,
        LDAP_SASL_QUIET = 2
    }
}

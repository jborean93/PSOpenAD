using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace PSOpenAD.Native
{
    internal static partial class Helpers
    {
        [StructLayout(LayoutKind.Sequential)]
        public struct gss_channel_bindings_struct
        {
            public int initiator_addrtype;
            public gss_buffer_desc initiator_address;
            public int acceptor_addrtype;
            public gss_buffer_desc acceptor_address;
            public gss_buffer_desc application_data;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct gss_OID_set_desc
        {
            public IntPtr count;
            public IntPtr elements;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct gss_OID_desc
        {
            public UInt32 length;
            public IntPtr elements;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct gss_buffer_desc
        {
            public IntPtr length;
            public IntPtr value;
        }
    }

    internal class GssapiCredential
    {
        public SafeGssapiCred Creds { get; }
        public UInt32 TimeToLive { get; }
        public List<byte[]> Mechanisms { get; }

        public GssapiCredential(SafeGssapiCred creds, UInt32 ttl, SafeHandle mechanisms)
        {
            Creds = creds;
            TimeToLive = ttl;

            using (mechanisms)
            {
                Helpers.gss_OID_set_desc set = Marshal.PtrToStructure<Helpers.gss_OID_set_desc>(mechanisms.DangerousGetHandle());
                Mechanisms = new List<byte[]>((int)set.count);
                IntPtr ptr = set.elements;
                for (int i = 0; i < Mechanisms.Count; i++)
                {
                    Helpers.gss_OID_desc member = Marshal.PtrToStructure<Helpers.gss_OID_desc>(ptr);
                    byte[] oid = new byte[member.length];
                    Marshal.Copy(member.elements, oid, 0, oid.Length);
                    Mechanisms[i] = oid;

                    ptr = IntPtr.Add(ptr, IntPtr.Size);
                }
            }
        }
    }

    internal class GssapiSecContext
    {
        public SafeGssapiSecContext Context { get; }
        public byte[] MechType { get; }
        public byte[] OutputToken { get; }
        public GssapiContextFlags Flags { get; }
        public Int32 TimeToLive { get; }
        public bool MoreNeeded { get; }

        public GssapiSecContext(SafeGssapiSecContext context, byte[] mechType, byte[] outputToken,
            GssapiContextFlags flags, int ttl, bool moreNeeded)
        {
            Context = context;
            MechType = mechType;
            OutputToken = outputToken;
            Flags = flags;
            TimeToLive = ttl;
            MoreNeeded = moreNeeded;
        }
    }

    internal static class GSSAPI
    {
        public const string LIB_GSSAPI = "PSOpenAD.libgssapi";

        // Name Types
        public static byte[] GSS_C_NT_HOSTBASED_SERVICE = new byte[] {
            0x2A, 0x86, 0x48, 0x86, 0xF7, 0x12, 0x01, 0x02, 0x01, 0x04
        }; // 1.2.840.113554.1.2.1.4

        public static byte[] GSS_C_NT_USER_NAME = new byte[] {
            0x2A, 0x86, 0x48, 0x86, 0xF7, 0x12, 0x01, 0x02, 0x01, 0x01
        }; // 1.2.840.113554.1.2.1.1

        // Mechanism OIDs
        public static byte[] KERBEROS = new byte[] {
            0x2A, 0x86, 0x48, 0x86, 0xF7, 0x12, 0x01, 0x02, 0x02
        }; // 1.2.840.113554.1.2.2

        public static byte[] SPNEGO = new byte[] {
            0x2B, 0x06, 0x01, 0x05, 0x05, 0x02
        }; // 1.3.6.1.5.5.2

        // Credential OIDs
        public static byte[] GSS_KRB5_CRED_NO_CI_FLAGS_X = new byte[] {
            0x2A, 0x85, 0x70, 0x2B, 0x0D, 0x1D
        }; // 1.2.752.43.13.29

        [DllImport(LIB_GSSAPI)]
        public static extern int gss_add_oid_set_member(
            out int min_stat,
            SafeHandle member,
            ref IntPtr target_set);

        [DllImport(LIB_GSSAPI)]
        public static extern int gss_acquire_cred(
            out int min_stat,
            SafeHandle desired_name,
            UInt32 ttl,
            SafeHandle mechs,
            GssapiCredUsage cred_usage,
            out SafeGssapiCred output_creds,
            out SafeGssapiOidSet actual_mechs,
            out UInt32 actual_ttl);

        [DllImport(LIB_GSSAPI)]
        public static extern int gss_acquire_cred_with_password(
            out int min_stat,
            SafeHandle desired_name,
            SafeHandle password,
            UInt32 ttl,
            SafeHandle desired_mechs,
            GssapiCredUsage cred_usage,
            out SafeGssapiCred output_creds,
            out SafeGssapiOidSet actual_mechs,
            out UInt32 actual_ttl);

        [DllImport(LIB_GSSAPI)]
        public static extern int gss_create_empty_oid_set(
            out int min_stat,
            out SafeGssapiOidSet target_set);

        [DllImport(LIB_GSSAPI)]
        public static extern int gss_delete_sec_context(
            out int min_stat,
            ref IntPtr context,
            IntPtr output_token);

        [DllImport(LIB_GSSAPI)]
        public static extern int gss_display_status(
            out int min_status,
            int status_value,
            int status_type,
            SafeHandle mech_type,
            ref int message_context,
            ref Helpers.gss_buffer_desc status_string);

        [DllImport(LIB_GSSAPI)]
        public static extern int gss_import_name(
            out int min_stat,
            SafeHandle input_buffer,
            SafeHandle name_type,
            out SafeGssapiName output_name);

        [DllImport(LIB_GSSAPI)]
        public static extern int gss_init_sec_context(
            out int minor_status,
            SafeGssapiCred cred_handle,
            ref SafeGssapiSecContext context_handle,
            SafeHandle target_name,
            SafeHandle mech_type,
            GssapiContextFlags req_flags,
            int time_req,
            SafeHandle input_chan_bindings,
            SafeHandle input_token,
            ref IntPtr actual_mech_type,
            ref Helpers.gss_buffer_desc output_token,
            out GssapiContextFlags ret_flags,
            out int time_rec);

        [DllImport(LIB_GSSAPI)]
        public static extern int gss_release_buffer(
            out int min_stat,
            ref Helpers.gss_buffer_desc buffer);

        [DllImport(LIB_GSSAPI)]
        public static extern int gss_release_cred(
            out int min_stat,
            ref IntPtr creds);

        [DllImport(LIB_GSSAPI)]
        public static extern int gss_release_name(
            out int min_stat,
            ref IntPtr name);

        [DllImport(LIB_GSSAPI)]
        public static extern int gss_release_oid_set(
            out int min_stat,
            ref IntPtr target_set);

        [DllImport(LIB_GSSAPI)]
        public static extern int gss_set_cred_option(
            out int min_status,
            SafeGssapiCred cred,
            SafeHandle desired_object,
            ref Helpers.gss_buffer_desc value);

        [DllImport(LIB_GSSAPI)]
        public static extern int gss_unwrap(
            out int minor_status,
            SafeGssapiSecContext context_handle,
            ref Helpers.gss_buffer_desc input_message,
            ref Helpers.gss_buffer_desc output_message,
            out int conf_state,
            out int qop_state);

        [DllImport(LIB_GSSAPI)]
        public static extern int gss_wrap(
            out int minor_status,
            SafeGssapiSecContext context_handle,
            int conf_req,
            int qop_req,
            ref Helpers.gss_buffer_desc input_message,
            out int conf_state,
            ref Helpers.gss_buffer_desc output_message);

        [DllImport(LIB_GSSAPI)]
        public static extern int gss_wrap_size_limit(
            out int minor_status,
            SafeGssapiSecContext context_handle,
            int conf_req,
            int qop_req,
            UInt32 size_req,
            out UInt32 max_size);

        /// <summary>Acquire GSSAPI credential</summary>
        /// <param name="name">The principal to get the cred for, if null the default principal is used.</param>
        /// <param name="ttl">The lifetime of the credential retrieved.</param>
        /// <param name="desiredMechs">A list of mechanisms the credential should work for.</param>
        /// <param name="usage">The usage type of the credential.</param>
        /// <returns>A handle to the retrieved GSSAPI credential.</returns>
        /// <exception cref="GSSAPIException">Failed to find the credential.</exception>
        public static GssapiCredential AcquireCred(SafeGssapiName? name, UInt32 ttl, List<byte[]> desiredMechs,
            GssapiCredUsage usage)
        {
            using SafeGssapiOidSet desiredMechSet = OIDSetBuffer(desiredMechs);

            if (name == null)
                name = new SafeGssapiName();

            int majorStatus = gss_acquire_cred(out var minorStatus, name, ttl, desiredMechSet, usage,
                out var outputCreds, out var actualMechs, out var actualTtls);
            if (majorStatus != 0)
                throw new GSSAPIException(majorStatus, minorStatus, "gss_acquire_cred");

            return new GssapiCredential(outputCreds, actualTtls, actualMechs);
        }

        /// <summary>Get a new GSSAPI credential with the password specified.</summary>
        /// <param name="name">The principal to get the cred for, if null the default principal is used.</param>
        /// <param name="password">The password used to generate the new credential.</param>
        /// <param name="ttl">The lifetime of the credential retrieved.</param>
        /// <param name="desiredMechs">A list of mechanisms the credential should work for.</param>
        /// <param name="usage">The usage type of the credential.</param>
        /// <returns>A handle to the retrieved GSSAPI credential.</returns>
        /// <exception cref="GSSAPIException">Failed to get a new credential with the creds specified.</exception>
        public static GssapiCredential AcquireCredWithPassword(SafeHandle name, string password, UInt32 ttl,
            List<byte[]> desiredMechs, GssapiCredUsage usage)
        {
            using SafeMemoryBuffer passwordBuffer = StringBuffer(password);
            using SafeGssapiOidSet desiredMechSet = OIDSetBuffer(desiredMechs);

            int majorStatus = gss_acquire_cred_with_password(out var minorStatus, name, passwordBuffer, ttl,
                desiredMechSet, usage, out var outputCreds, out var actualMechs, out var actualTtls);
            if (majorStatus != 0)
                throw new GSSAPIException(majorStatus, minorStatus, "gss_acquire_cred_with_password");

            return new GssapiCredential(outputCreds, actualTtls, actualMechs);
        }

        /// <summary>Get the GSSAPI error message for the error code.</summary>
        /// <param name="errorCode">The error code to get the status for.</param>
        /// <param name="isMajorCode">The error code is a major error code and not minor.</param>
        /// <param name="mech">Optional mech the error code is associated with.</param>
        /// <returns>The error message for the code specified.</returns>
        public static string DisplayStatus(int errorCode, bool isMajorCode, byte[]? mech)
        {
            Helpers.gss_buffer_desc msgBuffer = new Helpers.gss_buffer_desc();
            int statusType = isMajorCode ? 1 : 2; // GSS_C_GSS_CODE : GSS_C_MECH_CODE
            int messageContext = 0;

            using SafeMemoryBuffer mechOid = OIDBuffer(mech);
            List<string> lines = new List<string>();
            while (true)
            {
                int contextValue = messageContext;
                messageContext++;

                int majorStatus = gss_display_status(out var _, errorCode, statusType, mechOid,
                    ref contextValue, ref msgBuffer);

                // Cannot raise exception as it will result in a recursive operation.
                if (majorStatus != 0)
                    break;

                string? status = Marshal.PtrToStringUTF8(msgBuffer.value, (int)msgBuffer.length);
                if (!String.IsNullOrEmpty(status))
                    lines.Add(status);

                if (contextValue == 0)
                    break;
            }

            return String.Join(". ", lines);
        }

        /// <summary>Create a GSSAPI name object.</summary>
        /// <param name="name">The name to create the name object for.</param>
        /// <param nameType="The type of name to create."></param>
        /// <returns>The GSSAPI name buffer handle.</returns>
        /// <exception cref="GSSAPIException">Failed to create name object.</exception>
        public static SafeGssapiName ImportName(string name, byte[] nameType)
        {
            using SafeMemoryBuffer inputBuffer = StringBuffer(name);
            using SafeMemoryBuffer nameOID = OIDBuffer(nameType);
            int majorStatus = gss_import_name(out var minorStatus, inputBuffer, nameOID, out var outputName);
            if (majorStatus != 0)
                throw new GSSAPIException(majorStatus, minorStatus, "gss_import_name");

            return outputName;
        }

        public static GssapiSecContext InitSetContext(SafeGssapiCred? cred, SafeGssapiSecContext? context,
            SafeGssapiName targetName, byte[]? mechType, GssapiContextFlags reqFlags, int ttl,
            Helpers.gss_channel_bindings_struct? chanBindings, byte[]? inputToken)
        {
            cred ??= new SafeGssapiCred();
            context ??= new SafeGssapiSecContext();
            using SafeMemoryBuffer mechTypeBuffer = OIDBuffer(mechType);
            using SafeMemoryBuffer chanBindingBuffer = ChannelBindingBuffer(chanBindings);
            using SafeMemoryBuffer inputTokenBuffer = ByteBuffer(inputToken);
            Helpers.gss_buffer_desc outputTokenBuffer = new Helpers.gss_buffer_desc();
            IntPtr actualMechBuffer = IntPtr.Zero;

            int majorStatus = gss_init_sec_context(out var minorStatus, cred, ref context, targetName, mechTypeBuffer,
                reqFlags, ttl, chanBindingBuffer, inputTokenBuffer, ref actualMechBuffer, ref outputTokenBuffer,
                out var actualFlags, out var actualTTL);

            if (majorStatus != 0 && majorStatus != 1)
                throw new GSSAPIException(majorStatus, minorStatus, "gss_init_sec_context");

            try
            {
                byte[] actualMechType;
                if (actualMechBuffer == IntPtr.Zero)
                {
                    actualMechType = Array.Empty<byte>();
                }
                else
                {
                    unsafe
                    {
                        var actualMech = (Helpers.gss_OID_desc*)actualMechBuffer.ToPointer();
                        actualMechType = new byte[actualMech->length];
                        Marshal.Copy(actualMech->elements, actualMechType, 0, actualMechType.Length);
                    }
                }

                byte[] outputToken;
                if ((int)outputTokenBuffer.length > 0)
                {
                    outputToken = new byte[(int)outputTokenBuffer.length];
                    Marshal.Copy(outputTokenBuffer.value, outputToken, 0, outputToken.Length);
                }
                else
                {
                    outputToken = Array.Empty<byte>();
                }

                return new GssapiSecContext(context, actualMechType, outputToken, actualFlags, actualTTL,
                    majorStatus == 1);
            }
            finally
            {
                gss_release_buffer(out var minStatus2, ref outputTokenBuffer);
            }
        }

        /// <summary>Set an option on a GSSAPI credential.</summary>
        /// <param name="cred">The credential to set the option on.</param>
        /// <param name="oid">The credential option to set.</param>
        /// <exception cref="GSSAPIException">Failed to set option on the credential.</exception>
        public static void SetCredOption(SafeGssapiCred cred, byte[] oid)
        {
            using SafeMemoryBuffer objOID = OIDBuffer(oid);
            Helpers.gss_buffer_desc valueBuffer = new Helpers.gss_buffer_desc();
            int majorStatus = gss_set_cred_option(out var minorStatus, cred, objOID, ref valueBuffer);
            if (majorStatus != 0)
                throw new GSSAPIException(majorStatus, minorStatus, "gss_set_cred_option");
        }

        public static (byte[], bool, int) Unwrap(SafeGssapiSecContext context, byte[] inputMessage)
        {
            Helpers.gss_buffer_desc outputBuffer = new Helpers.gss_buffer_desc();
            int confState;
            int qopState;

            unsafe
            {
                fixed (byte* p = inputMessage)
                {
                    Helpers.gss_buffer_desc inputBuffer = new Helpers.gss_buffer_desc()
                    {
                        length = (IntPtr)inputMessage.Length,
                        value = (IntPtr)p,
                    };
                    int majorStatus = gss_unwrap(out var minorStatus, context, ref inputBuffer, ref outputBuffer,
                        out confState, out qopState);
                    if (majorStatus != 0)
                        throw new GSSAPIException(majorStatus, minorStatus, "gss_unwrap");
                }
            }

            try
            {
                byte[] output = new byte[(int)outputBuffer.length];
                Marshal.Copy(outputBuffer.value, output, 0, output.Length);

                return (output, confState == 1, qopState);
            }
            finally
            {
                gss_release_buffer(out var _, ref outputBuffer);
            }
        }

        public static (byte[], bool) Wrap(SafeGssapiSecContext context, bool confRequired, int qopReq,
            byte[] inputMessage)
        {
            Helpers.gss_buffer_desc outputBuffer = new Helpers.gss_buffer_desc();
            int confState;

            unsafe
            {
                fixed (byte* p = inputMessage)
                {
                    Helpers.gss_buffer_desc inputBuffer = new Helpers.gss_buffer_desc()
                    {
                        length = (IntPtr)inputMessage.Length,
                        value = (IntPtr)p,
                    };
                    int majorStatus = gss_wrap(out var minorStatus, context, confRequired ? 1 : 0, qopReq, ref inputBuffer,
                        out confState, ref outputBuffer);
                    if (majorStatus != 0)
                        throw new GSSAPIException(majorStatus, minorStatus, "gss_unwrap");
                }
            }

            try
            {
                byte[] output = new byte[(int)outputBuffer.length];
                Marshal.Copy(outputBuffer.value, output, 0, output.Length);

                return (output, confState == 1);
            }
            finally
            {
                gss_release_buffer(out var _, ref outputBuffer);
            }
        }

        public static UInt32 WrapSizeLimit(SafeGssapiSecContext context, bool confReq, int qopReq, UInt32 size)
        {
            int majorStatus = gss_wrap_size_limit(out var minorStatus, context, confReq ? 1 : 0, qopReq, size,
                out var maxSize);
            if (majorStatus != 0)
                throw new GSSAPIException(majorStatus, minorStatus, "gss_wrap_size_limit");

            return maxSize;
        }

        private static SafeMemoryBuffer ChannelBindingBuffer(Helpers.gss_channel_bindings_struct? bindings)
        {
            if (bindings == null)
                return new SafeMemoryBuffer();

            SafeMemoryBuffer buffer = new SafeMemoryBuffer(Marshal.SizeOf<Helpers.gss_channel_bindings_struct>());
            try
            {
                Marshal.StructureToPtr(bindings, buffer.DangerousGetHandle(), false);
            }
            catch
            {
                buffer.Dispose();
                throw;
            }

            return buffer;
        }

        private static SafeGssapiOidSet OIDSetBuffer(List<byte[]> oids)
        {
            int majorStatus = gss_create_empty_oid_set(out var minorStatus, out var desiredMechSet);
            if (majorStatus != 0)
                throw new GSSAPIException(majorStatus, minorStatus, "gss_create_empty_oid_set");

            try
            {
                IntPtr mechSetPtr = desiredMechSet.DangerousGetHandle();
                foreach (byte[] oid in oids)
                {
                    using SafeMemoryBuffer oidDesc = OIDBuffer(oid);
                    majorStatus = gss_add_oid_set_member(out minorStatus, oidDesc, ref mechSetPtr);
                    if (majorStatus != 0)
                        throw new GSSAPIException(majorStatus, minorStatus, "gss_add_oid_set_member");
                }
            }
            catch
            {
                desiredMechSet.Dispose();
                throw;
            }

            return desiredMechSet;
        }

        private static SafeMemoryBuffer OIDBuffer(byte[]? oid)
        {
            if (oid == null)
                return new SafeMemoryBuffer();

            int structSize = Marshal.SizeOf<Helpers.gss_OID_desc>();
            int oidLength = oid.Length;

            SafeMemoryBuffer nameTypeBuffer = new SafeMemoryBuffer(structSize + oidLength);
            try
            {
                Helpers.gss_OID_desc oidDesc = new Helpers.gss_OID_desc()
                {
                    length = (uint)oidLength,
                    elements = IntPtr.Zero,
                };

                if (oid != null)
                {
                    oidDesc.elements = IntPtr.Add(nameTypeBuffer.DangerousGetHandle(), structSize);
                    Marshal.Copy(oid, 0, oidDesc.elements, oid.Length);
                }

                Marshal.StructureToPtr(oidDesc, nameTypeBuffer.DangerousGetHandle(), false);
            }
            catch
            {
                nameTypeBuffer.Dispose();
                throw;
            }

            return nameTypeBuffer;
        }

        private static SafeMemoryBuffer ByteBuffer(byte[]? value)
        {
            if (value == null)
                return new SafeMemoryBuffer();

            int structSize = Marshal.SizeOf<Helpers.gss_buffer_desc>();
            SafeMemoryBuffer buffer = new SafeMemoryBuffer(structSize + value.Length);
            try
            {
                Helpers.gss_buffer_desc bufferDesc = new Helpers.gss_buffer_desc()
                {
                    length = new IntPtr(value.Length),
                    value = IntPtr.Add(buffer.DangerousGetHandle(), structSize),
                };
                Marshal.Copy(value, 0, bufferDesc.value, value.Length);
                Marshal.StructureToPtr(bufferDesc, buffer.DangerousGetHandle(), false);
            }
            catch
            {
                buffer.DangerousGetHandle();
                throw;
            }

            return buffer;
        }

        private static SafeMemoryBuffer StringBuffer(string value)
        {
            return ByteBuffer(Encoding.UTF8.GetBytes(value));
        }
    }

    public class GSSAPIException : Exception
    {
        public int MajorStatus { get; }

        public int MinorStatus { get; }

        public string? ErrorMessage { get; }

        internal GSSAPIException(int majorStatus, int minorStatus, string method, string? errorMessage = null)
            : base(GetExceptionMessage(majorStatus, minorStatus, method, errorMessage))
        {
            MajorStatus = majorStatus;
            MinorStatus = minorStatus;
            ErrorMessage = errorMessage;
        }

        private static string GetExceptionMessage(int majorStatus, int minorStatus, string? method,
            string? errorMessage)
        {
            method = String.IsNullOrWhiteSpace(method) ? "GSSAPI Call" : method;
            string majString = GSSAPI.DisplayStatus(majorStatus, true, null);
            string minString = GSSAPI.DisplayStatus(minorStatus, false, null);

            string msg = String.Format("{0} failed (Major Status {1} - {2}) (Minor Status {3} - {4})",
                method, majorStatus, majString, minorStatus, minString);
            if (!String.IsNullOrWhiteSpace(errorMessage))
                msg += $" - {errorMessage}";

            return msg;
        }
    }

    [Flags]
    internal enum GssapiContextFlags
    {
        GSS_C_DELEG_FLAG = 1,
        GSS_C_MUTUAL_FLAG = 2,
        GSS_C_REPLAY_FLAG = 4,
        GSS_C_SEQUENCE_FLAG = 8,
        GSS_C_CONF_FLAG = 16,
        GSS_C_INTEG_FLAG = 32,
        GSS_C_ANON_FLAG = 64,
        GSS_C_PROT_READY_FLAG = 128,
        GSS_C_TRANS_FLAG = 256,
        GSS_C_DELEG_POLICY_FLAG = 32768,
    }

    internal enum GssapiCredUsage
    {
        GSS_C_BOTH = 0,
        GSS_C_INITIATE = 1,
        GSS_C_ACCEPT = 2,
    }

    // internal class SafeGssapiBuffer : SafeHandle
    // {
    //     internal SafeGssapiBuffer() : base(IntPtr.Zero, true) { }

    //     public override bool IsInvalid => handle == IntPtr.Zero;

    //     protected override bool ReleaseHandle()
    //     {
    //         return GSSAPI.gss_release_buffer(out var _, handle) == 0;
    //     }
    // }

    internal class SafeGssapiCred : SafeHandle
    {
        internal SafeGssapiCred() : base(IntPtr.Zero, true) { }

        public override bool IsInvalid => handle == IntPtr.Zero;

        protected override bool ReleaseHandle()
        {
            return GSSAPI.gss_release_cred(out var _, ref handle) == 0;
        }
    }

    internal class SafeGssapiName : SafeHandle
    {
        internal SafeGssapiName() : base(IntPtr.Zero, true) { }

        public override bool IsInvalid => handle == IntPtr.Zero;

        protected override bool ReleaseHandle()
        {
            return GSSAPI.gss_release_name(out var _, ref handle) == 0;
        }
    }

    internal class SafeGssapiOidSet : SafeHandle
    {
        internal SafeGssapiOidSet() : base(IntPtr.Zero, true) { }

        public override bool IsInvalid => handle == IntPtr.Zero;

        protected override bool ReleaseHandle()
        {
            return GSSAPI.gss_release_oid_set(out var _, ref handle) == 0;
        }
    }

    internal class SafeGssapiSecContext : SafeHandle
    {
        internal SafeGssapiSecContext() : base(IntPtr.Zero, true) { }

        public override bool IsInvalid => handle == IntPtr.Zero;

        protected override bool ReleaseHandle()
        {
            return GSSAPI.gss_delete_sec_context(out var _, ref handle, IntPtr.Zero) == 0;
        }
    }
}

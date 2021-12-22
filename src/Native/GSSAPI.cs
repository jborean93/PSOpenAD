using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace PSOpenAD.Native
{
    internal static partial class Helpers
    {
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

    internal class GssapiCredential : IDisposable
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

        public void Dispose()
        {
            Creds.Dispose();
            GC.SuppressFinalize(this);
        }
        ~GssapiCredential() => Dispose();
    }

    internal static class GSSAPI
    {
        public const string LIB_GSSAPI = "PSOpenAD.libgssapi";

        // Name Types
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
        public static extern int gss_release_cred(
            out int min_stat,
            IntPtr creds);

        [DllImport(LIB_GSSAPI)]
        public static extern int gss_release_name(
            out int min_stat,
            IntPtr name);

        [DllImport(LIB_GSSAPI)]
        public static extern int gss_release_oid_set(
            out int min_stat,
            IntPtr target_set);

        [DllImport(LIB_GSSAPI)]
        public static extern int gss_set_cred_option(
            out int min_status,
            SafeGssapiCred cred,
            SafeHandle desired_object,
            ref Helpers.gss_buffer_desc value);

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
            StringBuilder msg = new StringBuilder();
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
                    msg.Append(status);

                if (contextValue == 0)
                    break;
            }

            return msg.ToString();
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
            int structSize = Marshal.SizeOf<Helpers.gss_OID_desc>();
            int oidLength = oid?.Length ?? 0;

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

        private static SafeMemoryBuffer StringBuffer(string value)
        {
            int structSize = Marshal.SizeOf<Helpers.gss_buffer_desc>();
            byte[] data = Encoding.UTF8.GetBytes(value);

            SafeMemoryBuffer buffer = new SafeMemoryBuffer(structSize + data.Length);
            try
            {
                Helpers.gss_buffer_desc bufferDesc = new Helpers.gss_buffer_desc()
                {
                    length = new IntPtr(data.Length),
                    value = IntPtr.Add(buffer.DangerousGetHandle(), structSize),
                };
                Marshal.Copy(data, 0, bufferDesc.value, data.Length);
                Marshal.StructureToPtr(bufferDesc, buffer.DangerousGetHandle(), false);
            }
            catch
            {
                buffer.DangerousGetHandle();
                throw;
            }

            return buffer;
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

    internal enum GssapiCredUsage
    {
        GSS_C_BOTH = 0,
        GSS_C_INITIATE = 1,
        GSS_C_ACCEPT = 2,
    }

    internal class SafeGssapiCred : SafeHandle
    {
        internal SafeGssapiCred() : base(IntPtr.Zero, true) { }

        public override bool IsInvalid => handle == IntPtr.Zero;

        protected override bool ReleaseHandle()
        {
            return GSSAPI.gss_release_cred(out var _, handle) == 0;
        }
    }

    internal class SafeGssapiName : SafeHandle
    {
        internal SafeGssapiName() : base(IntPtr.Zero, true) { }

        public override bool IsInvalid => handle == IntPtr.Zero;

        protected override bool ReleaseHandle()
        {
            return GSSAPI.gss_release_name(out var _, handle) == 0;
        }
    }

    internal class SafeGssapiOidSet : SafeHandle
    {
        internal SafeGssapiOidSet() : base(IntPtr.Zero, true) { }

        public override bool IsInvalid => handle == IntPtr.Zero;

        protected override bool ReleaseHandle()
        {
            using SafeMemoryBuffer setPtr = new SafeMemoryBuffer(IntPtr.Size);
            Marshal.WriteIntPtr(setPtr.DangerousGetHandle(), 0, handle);

            return GSSAPI.gss_release_oid_set(out var _, setPtr.DangerousGetHandle()) == 0;
        }
    }
}

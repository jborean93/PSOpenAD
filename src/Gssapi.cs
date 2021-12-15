using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace PSOpenAD
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

            public static explicit operator gss_OID_desc(GssapiOid oid)
            {
                return new gss_OID_desc()
                {
                    length = (UInt32)oid.Oid.Length,
                    elements = oid.RawOID.DangerousGetHandle(),
                };
            }
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
        public GssapiOid[] Mechanisms { get; }

        public GssapiCredential(SafeGssapiCred creds, UInt32 ttl, SafeHandle mechanisms)
        {
            Creds = creds;
            TimeToLive = ttl;

            using (mechanisms)
            {
                Helpers.gss_OID_set_desc set = Marshal.PtrToStructure<Helpers.gss_OID_set_desc>(mechanisms.DangerousGetHandle());
                Mechanisms = new GssapiOid[(int)set.count];
                IntPtr ptr = set.elements;
                for (int i = 0; i < Mechanisms.Length; i++)
                {
                    Helpers.gss_OID_desc member = Marshal.PtrToStructure<Helpers.gss_OID_desc>(ptr);
                    byte[] oid = new byte[member.length];
                    Marshal.Copy(member.elements, oid, 0, oid.Length);

                    Mechanisms[i] = new GssapiOid(oid);
                    ptr = IntPtr.Add(ptr, IntPtr.Size);
                }
            }
        }

        public void Dispose()
        {
            foreach (GssapiOid mech in Mechanisms)
                mech.Dispose();
            Creds.Dispose();
            GC.SuppressFinalize(this);
        }
        ~GssapiCredential() => Dispose();
    }

    public class GssapiOid : IDisposable
    {
        public byte[] Oid { get; }

        internal SafeMemoryBuffer RawOID { get; }

        public GssapiOid(byte[] oid)
        {
            Oid = oid;
            RawOID = new SafeMemoryBuffer(oid.Length);
            Marshal.Copy(oid, 0, RawOID.DangerousGetHandle(), oid.Length);
        }

        public void Dispose()
        {
            RawOID.Dispose();
            GC.SuppressFinalize(this);
        }
        ~GssapiOid() => Dispose();
    }

    internal static class Gssapi
    {
        private const string GSSAPI_LIB = "libgssapi_krb5.so.2";

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

        [DllImport(GSSAPI_LIB)]
        public static extern int gss_add_oid_set_member(
            out int min_stat,
            ref Helpers.gss_OID_desc member,
            SafeHandle target_set);

        [DllImport(GSSAPI_LIB)]
        public static extern int gss_acquire_cred(
            out int min_stat,
            SafeHandle desired_name,
            UInt32 ttl,
            SafeHandle mechs,
            GssapiCredUsage cred_usage,
            out SafeGssapiCred output_creds,
            out SafeGssapiOidSet actual_mechs,
            out UInt32 actual_ttl);

        [DllImport(GSSAPI_LIB)]
        public static extern int gss_acquire_cred_with_password(
            out int min_stat,
            SafeHandle desired_name,
            ref Helpers.gss_buffer_desc password,
            UInt32 ttl,
            SafeHandle desired_mechs,
            GssapiCredUsage cred_usage,
            out SafeGssapiCred output_creds,
            out SafeGssapiOidSet actual_mechs,
            out UInt32 actual_ttl);

        [DllImport(GSSAPI_LIB)]
        public static extern int gss_create_empty_oid_set(
            out int min_stat,
            out SafeGssapiOidSet target_set);

        [DllImport(GSSAPI_LIB)]
        public static extern int gss_display_status(
            out int min_status,
            int status_value,
            int status_type,
            SafeHandle mech_type,
            ref int message_context,
            ref Helpers.gss_buffer_desc status_string);

        [DllImport(GSSAPI_LIB)]
        public static extern int gss_import_name(
            out int min_stat,
            ref Helpers.gss_buffer_desc input_buffer,
            ref Helpers.gss_OID_desc name_type,
            out SafeGssapiName output_name);

        [DllImport(GSSAPI_LIB)]
        public static extern int gss_krb5_ccache_name(
            out int min_stat,
            string? name,
            out IntPtr out_name);

        [DllImport(GSSAPI_LIB)]
        public static extern int gss_release_cred(
            out int min_stat,
            IntPtr creds);

        [DllImport(GSSAPI_LIB)]
        public static extern int gss_release_name(
            out int min_stat,
            IntPtr name);

        [DllImport(GSSAPI_LIB)]
        public static extern int gss_release_oid_set(
            out int min_stat,
            IntPtr target_set);

        [DllImport(GSSAPI_LIB)]
        public static extern int gss_set_cred_option(
            out int min_status,
            SafeGssapiCred cred,
            ref Helpers.gss_OID_desc desired_object,
            ref Helpers.gss_buffer_desc value);

        public static GssapiCredential AcquireCred(SafeHandle? name, UInt32 ttl, List<GssapiOid> desiredMechs,
            GssapiCredUsage usage)
        {
            int majorStatus = gss_create_empty_oid_set(out var minorStatus, out var desiredMechSet);
            if (majorStatus != 0)
                throw new GSSAPIException(majorStatus, minorStatus, "gss_create_empty_oid_set");

            using (desiredMechSet)
            {
                using SafeMemoryBuffer mechPtr = new SafeMemoryBuffer(IntPtr.Size);
                Marshal.WriteIntPtr(mechPtr.DangerousGetHandle(), 0, desiredMechSet.DangerousGetHandle());

                foreach (GssapiOid mech in desiredMechs)
                {
                    Helpers.gss_OID_desc oidDesc = (Helpers.gss_OID_desc)mech;
                    majorStatus = gss_add_oid_set_member(out minorStatus, ref oidDesc, mechPtr);
                    if (majorStatus != 0)
                        throw new GSSAPIException(majorStatus, minorStatus, "gss_add_oid_set_member");
                }

                if (name == null)
                    name = new SafeGssapiName();

                majorStatus = gss_acquire_cred(out minorStatus, name, ttl, desiredMechSet, usage,
                    out var outputCreds, out var actualMechs, out var actualTtls);
                if (majorStatus != 0)
                    throw new GSSAPIException(majorStatus, minorStatus, "gss_acquire_cred");

                return new GssapiCredential(outputCreds, actualTtls, actualMechs);
            }
        }

        public static GssapiCredential AcquireCredWithPassword(SafeHandle name, string password, UInt32 ttl,
            List<GssapiOid> desiredMechs, GssapiCredUsage usage)
        {
            using SafeMemoryBuffer passwordPtr = new SafeMemoryBuffer(password);
            Helpers.gss_buffer_desc passwordBuffer = new Helpers.gss_buffer_desc()
            {
                length = (IntPtr)passwordPtr.Length,
                value = passwordPtr.DangerousGetHandle(),
            };

            int majorStatus = gss_create_empty_oid_set(out var minorStatus, out var desiredMechSet);
            if (majorStatus != 0)
                throw new GSSAPIException(majorStatus, minorStatus, "gss_create_empty_oid_set");

            using (desiredMechSet)
            {
                using SafeMemoryBuffer mechPtr = new SafeMemoryBuffer(IntPtr.Size);
                Marshal.WriteIntPtr(mechPtr.DangerousGetHandle(), 0, desiredMechSet.DangerousGetHandle());

                foreach (GssapiOid mech in desiredMechs)
                {
                    Helpers.gss_OID_desc oidDesc = (Helpers.gss_OID_desc)mech;
                    majorStatus = gss_add_oid_set_member(out minorStatus, ref oidDesc, mechPtr);
                    if (majorStatus != 0)
                        throw new GSSAPIException(majorStatus, minorStatus, "gss_add_oid_set_member");
                }

                majorStatus = gss_acquire_cred_with_password(out minorStatus, name, ref passwordBuffer, ttl,
                    desiredMechSet, usage, out var outputCreds, out var actualMechs, out var actualTtls);
                if (majorStatus != 0)
                    throw new GSSAPIException(majorStatus, minorStatus, "gss_acquire_cred_with_password");

                return new GssapiCredential(outputCreds, actualTtls, actualMechs);
            }
        }

        public static string DisplayStatus(int errorCode, bool isMajorCode, GssapiOid? mech)
        {
            Helpers.gss_buffer_desc msgBuffer = new Helpers.gss_buffer_desc();
            int statusType = isMajorCode ? 1 : 2; // GSS_C_GSS_CODE : GSS_C_MECH_CODE
            int messageContext = 0;

            SafeHandle mechOid;
            if (mech == null)
            {
                mechOid = new SafeMemoryBuffer(Marshal.SizeOf(typeof(Helpers.gss_OID_desc)));
                Marshal.StructureToPtr(new Helpers.gss_OID_desc(), mechOid.DangerousGetHandle(), false);
            }
            else
            {
                mechOid = mech.RawOID;
            }

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

        public static SafeGssapiName ImportName(string name, GssapiOid nameType)
        {
            using SafeMemoryBuffer nameBuffer = new SafeMemoryBuffer(name);
            Helpers.gss_buffer_desc inputBuffer = new Helpers.gss_buffer_desc()
            {
                length = new IntPtr(nameBuffer.Length),
                value = nameBuffer.DangerousGetHandle(),
            };
            Helpers.gss_OID_desc nameOid = (Helpers.gss_OID_desc)nameType;

            int majorStatus = gss_import_name(out var minorStatus, ref inputBuffer, ref nameOid,
                out var outputName);
            if (majorStatus != 0)
                throw new GSSAPIException(majorStatus, minorStatus, "gss_import_name");

            return outputName;
        }

        public static string? Krb5CCacheName(string? name)
        {
            int majorStatus = gss_krb5_ccache_name(out var minor_status, name, out var outName);
            if (majorStatus != 0)
                throw new GSSAPIException(majorStatus, minor_status, "gss_krb5_ccache_name");

            return Marshal.PtrToStringUTF8(outName);
        }

        public static void SetCredOption(SafeGssapiCred cred, GssapiOid obj)
        {
            Helpers.gss_OID_desc objectBuffer = (Helpers.gss_OID_desc)obj;
            Helpers.gss_buffer_desc valueBuffer = new Helpers.gss_buffer_desc();
            int majorStatus = gss_set_cred_option(out var minorStatus, cred, ref objectBuffer, ref valueBuffer);
            if (majorStatus != 0)
                throw new GSSAPIException(majorStatus, minorStatus, "gss_set_cred_option");
        }
    }

    public class GSSAPIException : Exception
    {
        public int MajorStatus { get; }

        public int MinorStatus { get; }

        public string? ErrorMessage { get; }

        public GSSAPIException(int majorStatus, int minorStatus, string method, string? errorMessage = null)
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
            string majString = Gssapi.DisplayStatus(majorStatus, true, null);
            string minString = Gssapi.DisplayStatus(minorStatus, false, null);

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
            return Gssapi.gss_release_cred(out var _, handle) == 0;
        }
    }

    internal class SafeGssapiName : SafeHandle
    {
        internal SafeGssapiName() : base(IntPtr.Zero, true) { }

        public override bool IsInvalid => handle == IntPtr.Zero;

        protected override bool ReleaseHandle()
        {
            return Gssapi.gss_release_name(out var _, handle) == 0;
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

            return Gssapi.gss_release_oid_set(out var _, setPtr.DangerousGetHandle()) == 0;
        }
    }
}

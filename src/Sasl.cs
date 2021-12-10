using System;
using System.Runtime.InteropServices;

namespace PSOpenAD
{
    internal static partial class Helpers
    {
        [StructLayout(LayoutKind.Sequential)]
        public struct sasl_interact
        {
            public SaslCallbackId id;
            public string challenge;
            public string prompt;
            public string defresult;
            public IntPtr result;
            public int len;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct sasl_secret
        {
            public int len;
            public IntPtr data;
        }
    }

    public abstract class SaslInteract
    {
        internal int SaslInteractProc(IntPtr ldap, int flags, IntPtr defaults, IntPtr interact)
        {
            IntPtr ptr = interact;
            while (true)
            {
                Helpers.sasl_interact callback = Marshal.PtrToStructure<Helpers.sasl_interact>(ptr);
                if (callback.id == SaslCallbackId.SASL_CB_LIST_END)
                    break;

                int resultOffset = (int)Marshal.OffsetOf<Helpers.sasl_interact>("result");
                int lenOffset = (int)Marshal.OffsetOf<Helpers.sasl_interact>("len");
                string val;
                switch (callback.id)
                {
                    case SaslCallbackId.SASL_CB_USER:
                        val = GetUser();
                        Marshal.WriteIntPtr(ptr, resultOffset, Marshal.StringToHGlobalAnsi(val));
                        Marshal.WriteInt32(ptr, lenOffset, val.Length);
                        break;
                    case SaslCallbackId.SASL_CB_AUTHNAME:
                        val = GetAuthName();
                        break;
                    case SaslCallbackId.SASL_CB_PASS:
                        val = ""; // sasl_secret
                        break;
                    case SaslCallbackId.SASL_CB_GETREALM:
                        val = GetRealm();
                        break;
                    // SASL_CB_ECHOPROMPT
                    // SASL_CB_NOECHOPROMPT
                    default:
                        throw new NotImplementedException();
                }

                ptr = IntPtr.Add(ptr, Marshal.SizeOf(typeof(Helpers.sasl_interact)));
            }

            return 0;
        }

        public virtual string GetUser() => throw new NotImplementedException();

        public virtual string GetAuthName() => throw new NotImplementedException();

        public virtual string GetPass() => throw new NotImplementedException();

        public virtual string GetRealm() => throw new NotImplementedException();
    }

    public enum SaslCallbackId
    {
        SASL_CB_LIST_END = 0,
        SASL_CB_GETOPT = 1,
        SASL_CB_LOG = 2,
        SASL_CB_GETPATH = 3,
        SASL_CB_VERIFYFILE = 4,
        SASL_CB_GETCONFPATH = 5,
        SASL_CB_USER = 0x4001,
        SASL_CB_AUTHNAME = 0x4002,
        SASL_CB_LANGUAGE = 0x4003,
        SASL_CB_PASS = 0x4004,
        SASL_CB_ECHOPROMPT = 0x4005,
        SASL_CB_NOECHOPROMPT = 0x4006,
        SASL_CB_CNONCE = 0x4007,
        SASL_CB_GETREALM = 0x4008,
        SASL_CB_PROXY_POLICY = 0x8001,
        SASL_CB_SERVER_USERDB_CHECKPASS = 0x8005,
        SASL_CB_SERVER_USERDB_SETPASS = 0x8006,
        SASL_CB_CANON_USER = 0x8007,
    }
}

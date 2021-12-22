using System;
using System.Runtime.InteropServices;

namespace PSOpenAD.Native
{
    internal static partial class Helpers
    {
        // [StructLayout(LayoutKind.Sequential)]
        // public struct sasl_interact
        // {
        //     public SaslCallbackId id;
        //     public string challenge;
        //     public string prompt;
        //     public string defresult;
        //     public IntPtr result;
        //     public int len;
        // }

        // [StructLayout(LayoutKind.Sequential)]
        // public struct sasl_secret
        // {
        //     public int len;
        //     public IntPtr data;
        // }

        [StructLayout(LayoutKind.Sequential)]
        public struct client_sasl_mechanism
        {
            public int version;
            public IntPtr plugname;
            public IntPtr plug;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct sasl_client_plug
        {
            public IntPtr mech_name;
            public int max_ssf;
            public SaslPluginSecurityFlags security_flags;
            public SaslPluginFeatures features;
        }
    }

    internal class SaslClientMechanism
    {
        public int Version { get; set; }
        public string Name { get; set; }
        public SaslClientPlugin Plugin { get; set; }

        public SaslClientMechanism(Helpers.client_sasl_mechanism mech)
        {
            Version = mech.version;
            Name = Marshal.PtrToStringUTF8(mech.plugname) ?? "";

            Helpers.sasl_client_plug clientPlug = Marshal.PtrToStructure<Helpers.sasl_client_plug>(mech.plug);
            Plugin = new SaslClientPlugin(clientPlug);
        }
    }

    internal class SaslClientPlugin
    {
        public string MechName { get; set; }
        public int MaxSSF { get; set; }
        public SaslPluginSecurityFlags SecurityFlags { get; set; } = SaslPluginSecurityFlags.NONE;
        public SaslPluginFeatures Features { get; set; } = SaslPluginFeatures.NONE;

        public SaslClientPlugin(Helpers.sasl_client_plug plug)
        {
            MechName = Marshal.PtrToStringUTF8(plug.mech_name) ?? "";
            MaxSSF = plug.max_ssf;
            SecurityFlags = plug.security_flags;
            Features = plug.features;
        }
    }

    internal static class CyrusSASL
    {
        public const string LIB_SASL = "PSOpenAD.libsasl";

        public delegate void sasl_client_info_callback_t(
            ref Helpers.client_sasl_mechanism m,
            SaslCallbackStage stage,
            IntPtr rock);

        public delegate void ClientInfoCallback(
            SaslCallbackStage stage,
            SaslClientMechanism? mech);

        [DllImport(LIB_SASL)]
        public static extern int sasl_client_init(
            IntPtr callbacks);

        [DllImport(LIB_SASL)]
        public static extern int sasl_client_plugin_info(
            string mech_list,
            [MarshalAs(UnmanagedType.FunctionPtr)] sasl_client_info_callback_t info_cb,
            IntPtr info_cb_rock);

        /// <summary>Initializes SASL.</summary>
        public static void ClientInit()
        {
            sasl_client_init(IntPtr.Zero);
        }

        /// <summary>Get information about each registered SASL client plugin.</summary>
        /// <param name="mechs">Space separated list of mechs to lookup.</param>
        /// <param name="callback">The callback that is run for every mech reported by SASL.</param>
        public static void ClientPluginInfo(string mechs, ClientInfoCallback callback)
        {
            int res = sasl_client_plugin_info(mechs,
                (ref Helpers.client_sasl_mechanism mech, SaslCallbackStage stage, IntPtr _) =>
                {
                    SaslClientMechanism? managedMech = null;
                    if (stage == SaslCallbackStage.SASL_INFO_LIST_MECH)
                        managedMech = new SaslClientMechanism(mech);

                    callback(stage, managedMech);
                },
                IntPtr.Zero);
        }
    }

    internal abstract class SaslInteract
    {
        internal int SaslInteractProc(IntPtr ldap, int flags, IntPtr defaults, IntPtr interact)
        {
            // We don't use the prompts for any SASL mech, currently we only care that PromptDone() is called.
            // IntPtr ptr = interact;
            // while (true)
            // {
            //     Helpers.sasl_interact callback = Marshal.PtrToStructure<Helpers.sasl_interact>(ptr);
            //     if (callback.id == SaslCallbackId.SASL_CB_LIST_END)
            //         break;

            //     int resultOffset = (int)Marshal.OffsetOf<Helpers.sasl_interact>("result");
            //     int lenOffset = (int)Marshal.OffsetOf<Helpers.sasl_interact>("len");
            //     string val;
            //     switch (callback.id)
            //     {
            //         case SaslCallbackId.SASL_CB_USER:
            //             val = GetUser();
            //             Marshal.WriteIntPtr(ptr, resultOffset, Marshal.StringToHGlobalAnsi(val));
            //             Marshal.WriteInt32(ptr, lenOffset, val.Length);
            //             break;
            //         case SaslCallbackId.SASL_CB_AUTHNAME:
            //             val = GetAuthName();
            //             break;
            //         case SaslCallbackId.SASL_CB_PASS:
            //             val = ""; // sasl_secret
            //             break;
            //         case SaslCallbackId.SASL_CB_GETREALM:
            //             val = GetRealm();
            //             break;
            //         // SASL_CB_ECHOPROMPT
            //         // SASL_CB_NOECHOPROMPT
            //         default:
            //             throw new NotImplementedException();
            //     }

            //     ptr = IntPtr.Add(ptr, Marshal.SizeOf(typeof(Helpers.sasl_interact)));
            // }

            PromptDone();

            return 0;
        }

        public virtual string GetUser() => throw new NotImplementedException();

        public virtual string GetAuthName() => throw new NotImplementedException();

        public virtual string GetPass() => throw new NotImplementedException();

        public virtual string GetRealm() => throw new NotImplementedException();

        public virtual void PromptDone() { }
    }

    // internal enum SaslCallbackId
    // {
    //     SASL_CB_LIST_END = 0,
    //     SASL_CB_GETOPT = 1,
    //     SASL_CB_LOG = 2,
    //     SASL_CB_GETPATH = 3,
    //     SASL_CB_VERIFYFILE = 4,
    //     SASL_CB_GETCONFPATH = 5,
    //     SASL_CB_USER = 0x4001,
    //     SASL_CB_AUTHNAME = 0x4002,
    //     SASL_CB_LANGUAGE = 0x4003,
    //     SASL_CB_PASS = 0x4004,
    //     SASL_CB_ECHOPROMPT = 0x4005,
    //     SASL_CB_NOECHOPROMPT = 0x4006,
    //     SASL_CB_CNONCE = 0x4007,
    //     SASL_CB_GETREALM = 0x4008,
    //     SASL_CB_PROXY_POLICY = 0x8001,
    //     SASL_CB_SERVER_USERDB_CHECKPASS = 0x8005,
    //     SASL_CB_SERVER_USERDB_SETPASS = 0x8006,
    //     SASL_CB_CANON_USER = 0x8007,
    // }

    internal enum SaslCallbackStage
    {
        SASL_INFO_LIST_START = 0,
        SASL_INFO_LIST_MECH = 1,
        SASL_INFO_LIST_END = 2,
    }

    [Flags]
    internal enum SaslPluginSecurityFlags
    {
        NONE = 0,
        SASL_SEC_NOPLAINTEXT = 0x0001,
        SASL_SEC_NOACTIVE = 0x0002,
        SASL_SEC_NODICTIONARY = 0x0004,
        SASL_SEC_FORWARD_SECRECY = 0x0008,
        SASL_SEC_NOANONYMOUS = 0x0010,
        SASL_SEC_PASS_CREDENTIALS = 0x0020,
        SASL_SEC_MUTUAL_AUTH = 0x0040,
    }

    [Flags]
    internal enum SaslPluginFeatures
    {
        NONE = 0,
        SASL_FEAT_NEEDSERVERFQDN = 0x0001,
        SASL_FEAT_WANT_CLIENT_FIRST = 0x0002,
        SASL_FEAT_WANT_SERVER_LAST = 0x0004,
        SASL_FEAT_INTERNAL_CLIENT_FIRST = 0x0008,
        SASL_FEAT_SERVER_FIRST = 0x0010,
        SASL_FEAT_ALLOWS_PROXY = 0x0020,
        SASL_FEAT_DONTUSE_USERPASSWD = 0x0080,
        SASL_FEAT_GSS_FRAMING = 0x0100,
        SASL_FEAT_CHANNEL_BINDING = 0x0800,
        SASL_FEAT_SUPPORTS_HTTP = 0x1000,
    }
}

using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Security.Authentication;
using System.Text;

namespace PSOpenAD.Native;

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

    // GSS.framework on x86_64 macOS is defined with pack(2) which complicates things a bit more. This is the only
    // struct that would be affected by this so needs special runtime handling when creating the struct. Note this
    // does not apply to the arm64 macOS, the define only applies to PowerPC (no longer relevant) and x86_64.
    // https://github.com/apple-oss-distributions/Heimdal/blob/5a776844a50fc09d714ba82ff7a88973c035b42b/lib/gssapi/gssapi/gssapi.h#L64-L67
    [StructLayout(LayoutKind.Sequential, Pack = 2)]
    public struct gss_channel_bindings_struct_macos
    {
        public int initiator_addrtype;
        public gss_buffer_desc initiator_address;
        public int acceptor_addrtype;
        public gss_buffer_desc acceptor_address;
        public gss_buffer_desc application_data;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct gss_OID_desc
    {
        public UInt32 length;
        public IntPtr elements;
    }

    // See above for why macOS needs this pack value.
    [StructLayout(LayoutKind.Sequential, Pack = 2)]
    public struct gss_OID_desc_macos
    {
        public UInt32 length;
        public IntPtr elements;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct gss_OID_set_desc
    {
        public IntPtr count;
        public IntPtr elements;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct gss_buffer_desc
    {
        public IntPtr length;
        public IntPtr value;
    }
}

/// <summary>Result of <c>AcquireCred</c> or <c>AcquireCredWithPassword</c>.</summary>
internal class GssapiCredential
{
    /// <summary>The handle to the GSSAPI credential.</summary>
    public SafeGssapiCred Creds { get; }

    /// <summary>The number of seconds until the credential expires.</summary>
    public UInt32 TimeToLive { get; }

    /// <summary>The GSSAPI mechanisms that the credential supports.</summary>
    public List<byte[]> Mechanisms { get; }

    public GssapiCredential(SafeGssapiCred creds, UInt32 ttl, SafeHandle mechanisms)
    {
        Creds = creds;
        TimeToLive = ttl;

        using (mechanisms)
        {
            unsafe
            {
                Helpers.gss_OID_set_desc* set = (Helpers.gss_OID_set_desc*)mechanisms.DangerousGetHandle();
                Mechanisms = new List<byte[]>((int)set->count);

                if (GSSAPI.MACOS_PACKED_STRUCT)
                {
                    Span<Helpers.gss_OID_desc_macos> oids = new(set->elements.ToPointer(), (int)set->count);
                    foreach (Helpers.gss_OID_desc_macos memers in oids)
                    {
                        byte[] oid = new Span<byte>(memers.elements.ToPointer(), (int)memers.length).ToArray();
                        Mechanisms.Add(oid);
                    }
                }
                else
                {
                    Span<Helpers.gss_OID_desc> oids = new(set->elements.ToPointer(), (int)set->count);
                    foreach (Helpers.gss_OID_desc memers in oids)
                    {
                        byte[] oid = new Span<byte>(memers.elements.ToPointer(), (int)memers.length).ToArray();
                        Mechanisms.Add(oid);
                    }
                }
            }
        }
    }
}

/// <summary>Result of <c>InitSecContext</c>.</summary>
internal class GssapiSecContext
{
    /// <summary>The handle to the GSSAPI security context.</summary>
    public SafeGssapiSecContext Context { get; }

    /// <summary>The GSSAPI mech the context used.</summary>
    public byte[] MechType { get; }

    /// <summary>The return buffer from the GSSAPI call.</summary>
    public byte[] OutputToken { get; }

    /// <summary>The attributes used to describe the functionality available on the context.</summary>
    public GssapiContextFlags Flags { get; }

    /// <summary>The number of seconds until the context expires.</summary>
    public Int32 TimeToLive { get; }

    /// <summary>Whether more data is neded from the acceptor to complete the context.</summary>
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

    public static byte[] NTLM = new byte[] {
        0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0A
    }; // 1.3.6.1.4.1.311.2.2.10

    public static byte[] SPNEGO = new byte[] {
        0x2B, 0x06, 0x01, 0x05, 0x05, 0x02
    }; // 1.3.6.1.5.5.2

    // Credential OIDs
    public static byte[] GSS_KRB5_CRED_NO_CI_FLAGS_X = new byte[] {
        0x2A, 0x85, 0x70, 0x2B, 0x0D, 0x1D
    }; // 1.2.752.43.13.29

    // macOS on x86_64 need to use a specially packed structure, this just simplifies the check.
    public static bool MACOS_PACKED_STRUCT = (
        RuntimeInformation.IsOSPlatform(OSPlatform.OSX) &&
        (
            // Doesn't apply to arm64 runtimes.
            RuntimeInformation.ProcessArchitecture == Architecture.X86 ||
            RuntimeInformation.ProcessArchitecture == Architecture.X64
        )
    );

    [DllImport(LIB_GSSAPI)]
    public static unsafe extern int gss_add_oid_set_member(
        out int min_stat,
        SafeHandle member,
        ref Helpers.gss_OID_set_desc* target_set);

    [DllImport(LIB_GSSAPI)]
    public static unsafe extern int gss_acquire_cred(
        out int min_stat,
        SafeHandle desired_name,
        UInt32 ttl,
        Helpers.gss_OID_set_desc* mechs,
        GssapiCredUsage cred_usage,
        out SafeGssapiCred output_creds,
        out SafeGssapiOidSet actual_mechs,
        out UInt32 actual_ttl);

    [DllImport(LIB_GSSAPI)]
    public static unsafe extern int gss_acquire_cred_with_password(
        out int min_stat,
        SafeHandle desired_name,
        ref Helpers.gss_buffer_desc password,
        UInt32 ttl,
        Helpers.gss_OID_set_desc* desired_mechs,
        GssapiCredUsage cred_usage,
        out SafeGssapiCred output_creds,
        out SafeGssapiOidSet actual_mechs,
        out UInt32 actual_ttl);

    [DllImport(LIB_GSSAPI)]
    public static unsafe extern int gss_create_empty_oid_set(
        out int min_stat,
        out Helpers.gss_OID_set_desc* target_set);

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
        ref Helpers.gss_buffer_desc input_buffer,
        SafeHandle name_type,
        out SafeGssapiName output_name);

    [DllImport(LIB_GSSAPI)]
    public static unsafe extern int gss_init_sec_context(
        out int minor_status,
        SafeGssapiCred cred_handle,
        ref SafeGssapiSecContext context_handle,
        SafeHandle target_name,
        SafeHandle mech_type,
        GssapiContextFlags req_flags,
        int time_req,
        SafeHandle input_chan_bindings,
        Helpers.gss_buffer_desc* input_token,
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
    public static unsafe extern int gss_release_oid_set(
        out int min_stat,
        ref Helpers.gss_OID_set_desc* target_set);

    [DllImport(LIB_GSSAPI)]
    public static extern int gss_set_cred_option(
        out int min_status,
        ref SafeGssapiCred cred,
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

    /// <summary>Acquire GSSAPI credential.</summary>
    /// <param name="name">The principal to get the cred for, if null the default principal is used.</param>
    /// <param name="ttl">The lifetime of the credential retrieved.</param>
    /// <param name="desiredMechs">A list of mechanisms the credential should work for.</param>
    /// <param name="usage">The usage type of the credential.</param>
    /// <returns>A handle to the retrieved GSSAPI credential.</returns>
    /// <exception cref="GSSAPIException">Failed to find the credential.</exception>
    public static GssapiCredential AcquireCred(SafeGssapiName? name, UInt32 ttl, IList<byte[]>? desiredMechs,
        GssapiCredUsage usage)
    {
        if (name == null)
            name = new SafeGssapiName();

        unsafe
        {
            Helpers.gss_OID_set_desc* oidSet = CreateOIDSet(desiredMechs);
            try
            {
                int majorStatus = gss_acquire_cred(out var minorStatus, name, ttl, oidSet, usage,
                    out var outputCreds, out var actualMechs, out var actualTtls);
                if (majorStatus != 0)
                    throw new GSSAPIException(majorStatus, minorStatus, "gss_acquire_cred");

                return new GssapiCredential(outputCreds, actualTtls, actualMechs);
            }
            finally
            {
                gss_release_oid_set(out var _, ref oidSet);
            }
        }
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
        IList<byte[]> desiredMechs, GssapiCredUsage usage)
    {
        byte[] passBytes = Encoding.UTF8.GetBytes(password);
        unsafe
        {
            Helpers.gss_OID_set_desc* oidSet = CreateOIDSet(desiredMechs);
            try
            {
                fixed (byte* passPtr = passBytes)
                {
                    Helpers.gss_buffer_desc passBuffer = new()
                    {
                        length = new IntPtr(passBytes.Length),
                        value = (IntPtr)passPtr,
                    };

                    int majorStatus = gss_acquire_cred_with_password(out var minorStatus, name, ref passBuffer,
                        ttl, oidSet, usage, out var outputCreds, out var actualMechs, out var actualTtls);
                    if (majorStatus != 0)
                        throw new GSSAPIException(majorStatus, minorStatus, "gss_acquire_cred_with_password");

                    return new GssapiCredential(outputCreds, actualTtls, actualMechs);
                }
            }
            finally
            {
                gss_release_oid_set(out var _, ref oidSet);
            }
        }
    }

    /// <summary>Get the GSSAPI error message for the error code.</summary>
    /// <param name="errorCode">The error code to get the status for.</param>
    /// <param name="isMajorCode">The error code is a major error code and not minor.</param>
    /// <param name="mech">Optional mech the error code is associated with.</param>
    /// <returns>The error message for the code specified.</returns>
    public static string DisplayStatus(int errorCode, bool isMajorCode, byte[]? mech)
    {
        Helpers.gss_buffer_desc msgBuffer = new();
        int statusType = isMajorCode ? 1 : 2; // GSS_C_GSS_CODE : GSS_C_MECH_CODE
        int messageContext = 0;

        unsafe
        {
            fixed (byte* mechPtr = mech)
            {
                SafeHandle mechBuffer = CreateOIDBuffer(mechPtr, mech?.Length ?? 0);

                List<string> lines = new();
                while (true)
                {
                    int contextValue = messageContext;
                    messageContext++;

                    int majorStatus = gss_display_status(out var _, errorCode, statusType, mechBuffer,
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
        }
    }

    /// <summary>Create a GSSAPI name object.</summary>
    /// <param name="name">The name to create the name object for.</param>
    /// <param nameType="The type of name to create."></param>
    /// <returns>The GSSAPI name buffer handle.</returns>
    /// <exception cref="GSSAPIException">Failed to create name object.</exception>
    public static SafeGssapiName ImportName(string name, ReadOnlySpan<byte> nameType)
    {
        byte[] nameBytes = Encoding.UTF8.GetBytes(name);

        unsafe
        {
            fixed (byte* nameTypePtr = nameType, namePtr = nameBytes)
            {
                Helpers.gss_buffer_desc nameBuffer = new()
                {
                    length = new IntPtr(nameBytes.Length),
                    value = (IntPtr)namePtr,
                };

                using SafeHandle nameTypeBuffer = CreateOIDBuffer(nameTypePtr, nameType.Length);
                int majorStatus = gss_import_name(out var minorStatus, ref nameBuffer, nameTypeBuffer,
                    out var outputName);
                if (majorStatus != 0)
                    throw new GSSAPIException(majorStatus, minorStatus, "gss_import_name");

                return outputName;
            }
        }
    }

    /// <summary>Initiates a security context or processes a new token on an existing context.</summary>
    /// <param name="cred">
    /// The credential handle to be used with the context. Set to null to use <c>GSS_C_NO_CREDENTIAL</c>.
    /// </param>
    /// <param name="context">
    /// The context handle for the operation. The first call should be set to <c>null</c> while subsequence calls
    /// use the context returned from the first call.
    /// </param>
    /// <param name="targetName">The target name of the acceptor, for Kerberos this is the SPN.</param>
    /// <param name="mechType">The desired security mechanism OID or null for <c>GSS_C_NO_OID</c>.</param>
    /// <param name="reqFlags">Request flags to set.</param>
    /// <param name="ttl">The lifetime of the context retrieved.</param>
    /// <param name="chanBindings">Optional channel bindings to bind to the context.</param>
    /// <param name="inputToken">Optional token received from the acceptor or null for <c>GSS_C_NO_BUFFER</c>.</param>
    /// <returns>A handle to the retrieved GSSAPI security context.</returns>
    /// <exception cref="GSSAPIException">Failed to initiate/step the security context.</exception>
    public static GssapiSecContext InitSecContext(SafeGssapiCred? cred, SafeGssapiSecContext? context,
        SafeGssapiName targetName, byte[]? mechType, GssapiContextFlags reqFlags, int ttl,
        ChannelBindings? chanBindings, byte[]? inputToken)
    {
        cred ??= new SafeGssapiCred();
        context ??= new SafeGssapiSecContext();
        Helpers.gss_buffer_desc outputTokenBuffer = new();
        IntPtr actualMechBuffer = IntPtr.Zero;

        GssapiContextFlags actualFlags;
        int actualTTL;
        bool continueNeeded;
        unsafe
        {
            fixed (byte* mechTypePtr = mechType,
                initiatorAddr = chanBindings?.InitiatorAddr,
                acceptorAddr = chanBindings?.AcceptorAddr,
                appData = chanBindings?.ApplicationData,
                inputTokenPtr = inputToken)
            {
                SafeHandle mechBuffer = CreateOIDBuffer(mechTypePtr, mechType?.Length ?? 0);
                SafeHandle chanBindingBuffer = CreateChanBindingBuffer(chanBindings, initiatorAddr, acceptorAddr,
                    appData);

                Helpers.gss_buffer_desc* inputStruct = null;
                if (inputToken != null)
                {
                    Helpers.gss_buffer_desc inputBuffer = new()
                    {
                        length = new IntPtr(inputToken.Length),
                        value = (IntPtr)inputTokenPtr,
                    };
                    inputStruct = &inputBuffer;
                }

                int majorStatus = gss_init_sec_context(out var minorStatus, cred, ref context, targetName, mechBuffer,
                    reqFlags, ttl, chanBindingBuffer, inputStruct, ref actualMechBuffer, ref outputTokenBuffer,
                    out actualFlags, out actualTTL);

                if (majorStatus != 0 && majorStatus != 1)
                    throw new GSSAPIException(majorStatus, minorStatus, "gss_init_sec_context");

                continueNeeded = majorStatus == 1;
            }
        }

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
                    if (MACOS_PACKED_STRUCT)
                    {
                        var actualMech = (Helpers.gss_OID_desc_macos*)actualMechBuffer.ToPointer();
                        actualMechType = new byte[actualMech->length];
                        Marshal.Copy(actualMech->elements, actualMechType, 0, actualMechType.Length);
                    }
                    else
                    {
                        var actualMech = (Helpers.gss_OID_desc*)actualMechBuffer.ToPointer();
                        actualMechType = new byte[actualMech->length];
                        Marshal.Copy(actualMech->elements, actualMechType, 0, actualMechType.Length);
                    }
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
                continueNeeded);
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
    public static void SetCredOption(SafeGssapiCred cred, ReadOnlySpan<byte> oid)
    {
        unsafe
        {
            fixed (byte* oidPtr = oid)
            {
                SafeHandle oidBuffer = CreateOIDBuffer(oidPtr, oid.Length);
                Helpers.gss_buffer_desc valueBuffer = new();

                int majorStatus = gss_set_cred_option(out var minorStatus, ref cred, oidBuffer, ref valueBuffer);
                if (majorStatus != 0)
                    throw new GSSAPIException(majorStatus, minorStatus, "gss_set_cred_option");
            }
        }
    }

    /// <summary>Unwraps a wrapped message from the peer.</summary>
    /// <param name="context">The context handle that was used to wrap the message.</param>
    /// <param name="inputMessage">The wrapped message to unwrap.</param>
    /// <returns>
    /// A tuple that contains:
    ///   The unwrapped message.
    ///   Whether the input message was encrypted.
    ///   The QOP applied to the input message.
    /// </returns>
    /// <exception cref="GSSAPIException">Failed to initiate/step the security context.</exception>
    public static (byte[], bool, int) Unwrap(SafeGssapiSecContext context, ReadOnlySpan<byte> inputMessage)
    {
        Helpers.gss_buffer_desc outputBuffer = new();
        int confState;
        int qopState;

        unsafe
        {
            fixed (byte* p = inputMessage)
            {
                Helpers.gss_buffer_desc inputBuffer = new()
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

    /// <summary>Wraps (signs or encrypts) a message to send to the peer.</summary>
    /// <param name="context">The context handle that is used to wrap the message.</param>
    /// <param name="confReq">Whether to encrypt the message or just sign it.</param>
    /// <param name="qopReq">The QOP requested for the message.</param>
    /// <param name="inputMessage">The message to encrypt.</param>
    /// <returns>
    /// A tuple the contains:
    ///   The wrapped message.
    ///   Whether the input message was encrypted (true) or just signed (false).
    /// </returns>
    /// <exception cref="GSSAPIException">Failed to initiate/step the security context.</exception>
    public static (byte[], bool) Wrap(SafeGssapiSecContext context, bool confReq, int qopReq,
        ReadOnlySpan<byte> inputMessage)
    {
        Helpers.gss_buffer_desc outputBuffer = new();
        int confState;

        unsafe
        {
            fixed (byte* p = inputMessage)
            {
                Helpers.gss_buffer_desc inputBuffer = new()
                {
                    length = (IntPtr)inputMessage.Length,
                    value = (IntPtr)p,
                };
                int majorStatus = gss_wrap(out var minorStatus, context, confReq ? 1 : 0, qopReq, ref inputBuffer,
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

    /// <summary>Gets the larges message size that can be processed by <c>gss_wrap</c>.</summary>
    /// <param name="context">The context handle that is used to wrap the message.</param>
    /// <param name="confReq">Whether encryption will be requested to encrypt the message or just sign it.</param>
    /// <param name="qopReq">The QOP requested for the message to be wrapped.</param>
    /// <param name="size">The maximum output size that can be generated.</param>
    /// <returns>The maximum message size that can be processed.</returns>
    /// <exception cref="GSSAPIException">Failed to initiate/step the security context.</exception>
    public static UInt32 WrapSizeLimit(SafeGssapiSecContext context, bool confReq, int qopReq, UInt32 size)
    {
        int majorStatus = gss_wrap_size_limit(out var minorStatus, context, confReq ? 1 : 0, qopReq, size,
            out var maxSize);
        if (majorStatus != 0)
            throw new GSSAPIException(majorStatus, minorStatus, "gss_wrap_size_limit");

        return maxSize;
    }

    private static unsafe SafeHandle CreateChanBindingBuffer(ChannelBindings? bindings, byte* initiatorAddr,
        byte* acceptorAddr, byte* applicationData)
    {
        if (bindings == null)
            return new SafeMemoryBuffer();

        if (MACOS_PACKED_STRUCT)
        {
            // Need the pack 2 structure to properly set this up.
            SafeMemoryBuffer buffer = new(Marshal.SizeOf<Helpers.gss_channel_bindings_struct_macos>());

            var cb = (Helpers.gss_channel_bindings_struct_macos*)buffer.DangerousGetHandle().ToPointer();
            cb->initiator_addrtype = bindings.InitiatorAddrType;
            cb->initiator_address.length = new IntPtr(bindings.InitiatorAddr?.Length ?? 0);
            cb->initiator_address.value = (IntPtr)initiatorAddr;
            cb->acceptor_addrtype = bindings.AcceptorAddrType;
            cb->acceptor_address.length = new IntPtr(bindings.AcceptorAddr?.Length ?? 0);
            cb->acceptor_address.value = (IntPtr)acceptorAddr;
            cb->application_data.length = new IntPtr(bindings.ApplicationData?.Length ?? 0);
            cb->application_data.value = (IntPtr)applicationData;

            return buffer;
        }
        else
        {
            SafeMemoryBuffer buffer = new(Marshal.SizeOf<Helpers.gss_channel_bindings_struct>());

            var cb = (Helpers.gss_channel_bindings_struct*)buffer.DangerousGetHandle().ToPointer();
            cb->initiator_addrtype = bindings.InitiatorAddrType;
            cb->initiator_address.length = new IntPtr(bindings.InitiatorAddr?.Length ?? 0);
            cb->initiator_address.value = (IntPtr)initiatorAddr;
            cb->acceptor_addrtype = bindings.AcceptorAddrType;
            cb->acceptor_address.length = new IntPtr(bindings.AcceptorAddr?.Length ?? 0);
            cb->acceptor_address.value = (IntPtr)acceptorAddr;
            cb->application_data.length = new IntPtr(bindings.ApplicationData?.Length ?? 0);
            cb->application_data.value = (IntPtr)applicationData;

            return buffer;
        }
    }

    private static unsafe SafeHandle CreateOIDBuffer(byte* oid, int length)
    {
        if (oid == null)
            return new SafeMemoryBuffer();

        if (MACOS_PACKED_STRUCT)
        {
            // Need the pack 2 structure to properly set this up.
            SafeMemoryBuffer buffer = new(Marshal.SizeOf<Helpers.gss_OID_desc_macos>());
            var oidBuffer = (Helpers.gss_OID_desc_macos*)buffer.DangerousGetHandle().ToPointer();
            oidBuffer->length = (uint)length;
            oidBuffer->elements = (IntPtr)oid;

            return buffer;
        }
        else
        {
            SafeMemoryBuffer buffer = new(Marshal.SizeOf<Helpers.gss_OID_desc>());
            var oidBuffer = (Helpers.gss_OID_desc*)buffer.DangerousGetHandle().ToPointer();
            oidBuffer->length = (uint)length;
            oidBuffer->elements = (IntPtr)oid;

            return buffer;
        }
    }

    private static unsafe Helpers.gss_OID_set_desc* CreateOIDSet(IList<byte[]>? oids)
    {
        if (oids == null)
            return null;

        int majorStatus = gss_create_empty_oid_set(out var minorStatus, out var setBuffer);
        if (majorStatus != 0)
            throw new GSSAPIException(majorStatus, minorStatus, "gss_create_empty_oid_set");

        try
        {
            foreach (byte[] oid in oids)
            {
                fixed (byte* oidPtr = oid)
                {
                    SafeHandle oidBuffer = CreateOIDBuffer(oidPtr, oid.Length);
                    majorStatus = gss_add_oid_set_member(out minorStatus, oidBuffer, ref setBuffer);
                    if (majorStatus != 0)
                        throw new GSSAPIException(majorStatus, minorStatus, "gss_add_oid_set_member");
                }
            }
        }
        catch
        {
            gss_release_oid_set(out var _, ref setBuffer);
            throw;
        }

        return setBuffer;
    }
}

public class GSSAPIException : AuthenticationException
{
    public int MajorStatus { get; } = -1;

    public int MinorStatus { get; } = -1;

    public GSSAPIException() { }

    public GSSAPIException(string message) : base(message) { }

    public GSSAPIException(string message, Exception innerException) :
        base(message, innerException)
    { }

    public GSSAPIException(int majorStatus, int minorStatus, string method)
        : base(GetExceptionMessage(majorStatus, minorStatus, method))
    {
        MajorStatus = majorStatus;
        MinorStatus = minorStatus;
    }

    private static string GetExceptionMessage(int majorStatus, int minorStatus, string? method)
    {
        method = String.IsNullOrWhiteSpace(method) ? "GSSAPI Call" : method;
        string majString = GSSAPI.DisplayStatus(majorStatus, true, null);
        string minString = GSSAPI.DisplayStatus(minorStatus, false, null);

        return String.Format("{0} failed (Major Status {1} - {2}) (Minor Status {3} - {4})",
            method, majorStatus, majString, minorStatus, minString);
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
        unsafe
        {
            Helpers.gss_OID_set_desc* oidSet = (Helpers.gss_OID_set_desc*)handle;

            return GSSAPI.gss_release_oid_set(out var _, ref oidSet) == 0;
        }
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

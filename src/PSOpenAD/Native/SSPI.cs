using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Authentication;

namespace PSOpenAD.Native;

internal static partial class Helpers
{
    [StructLayout(LayoutKind.Sequential)]
    public struct SEC_CHANNEL_BINDINGS
    {
        public UInt32 dwInitiatorAddrType;
        public UInt32 cbInitiatorLength;
        public UInt32 dwInitiatorOffset;
        public UInt32 dwAcceptorAddrType;
        public UInt32 cbAcceptorLength;
        public UInt32 dwAcceptorOffset;
        public UInt32 cbApplicationDataLength;
        public UInt32 dwApplicationDataOffset;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct SEC_WINNT_AUTH_IDENTITY_W
    {
        public unsafe char* User;
        public UInt32 UserLength;
        public unsafe char* Domain;
        public UInt32 DomainLength;
        public unsafe char* Password;
        public UInt32 PasswordLength;
        public WinNTAuthIdentityFlags Flags;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct SECURITY_INTEGER
    {
        public UInt32 LowPart;
        public Int32 HighPart;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct SecBufferDesc
    {
        public UInt32 ulVersion;
        public UInt32 cBuffers;
        public IntPtr pBuffers;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct SecBuffer
    {
        public UInt32 cbBuffer;
        public UInt32 BufferType;
        public IntPtr pvBuffer;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct SecHandle
    {
        public UIntPtr dwLower;
        public UIntPtr dwUpper;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct SecPkgContext_Sizes
    {
        public UInt32 cbMaxToken;
        public UInt32 cbMaxSignature;
        public UInt32 cbBlockSize;
        public UInt32 cbSecurityTrailer;
    }
}

/// <summary>Result of <c>AcquireCredentialsHandle</c>.</summary>
internal class SspiCredential
{
    /// <summary>The handle to the SSPI credential.</summary>
    public SafeSspiCredentialHandle Creds { get; }

    /// <summary>The number of ticks (100s of nanoseconds) since 1601-01-01 until the credential expires.</summary>
    public UInt64 Expiry { get; }

    public SspiCredential(SafeSspiCredentialHandle creds, UInt64 expiry)
    {
        Creds = creds;
        Expiry = expiry;
    }
}

/// <summary>Result of <c>InitializeSecurityContext</c>.</summary>
internal class SspiSecContext
{
    /// <summary>The handle to the SSPI security context.</summary>
    public SafeSspiContextHandle Context { get; }

    /// <summary>The return buffer values from the SSPI call.</summary>
    public byte[][] OutputBuffers { get; }

    /// <summary>The number of ticks (100s of nanoseconds) since 1601-01-01 until the context expires.</summary>
    public UInt64 Expiry { get; }

    /// <summary>The attributes used to describe the functionality available on the context.</summary>
    public InitiatorContextReturnFlags Flags { get; }

    /// <summary>Whether more data is needed from the acceptor to complete the context.</summary>
    public bool MoreNeeded { get; }

    public SspiSecContext(SafeSspiContextHandle context, byte[][] outputBuffers, UInt64 expiry,
        InitiatorContextReturnFlags flags, bool moreNeeded)
    {
        Context = context;
        OutputBuffers = outputBuffers;
        Expiry = expiry;
        Flags = flags;
        MoreNeeded = moreNeeded;
    }
}

internal static class SSPI
{
    private const Int32 SEC_I_CONTINUE_NEEDED = 0x00090312;

    [DllImport("Secur32.dll", CharSet = CharSet.Unicode)]
    private static unsafe extern Int32 AcquireCredentialsHandleW(
        [MarshalAs(UnmanagedType.LPWStr)] string? pszPrincipal,
        [MarshalAs(UnmanagedType.LPWStr)] string pPackage,
        CredentialUse fCredentialUse,
        IntPtr pvLogonId,
        Helpers.SEC_WINNT_AUTH_IDENTITY_W* pAuthData,
        IntPtr pGetKeyFn,
        IntPtr pvGetKeyArgument,
        SafeSspiCredentialHandle phCredential,
        out Helpers.SECURITY_INTEGER ptsExpiry);

    [DllImport("Secur32.dll", EntryPoint = "DecryptMessage")]
    private static extern Int32 DecryptMessageNative(
        SafeSspiContextHandle phContext,
        ref Helpers.SecBufferDesc pMessage,
        UInt32 MessageSeqNo,
        out UInt32 pfQOP);

    [DllImport("Secur32.dll")]
    public static extern Int32 DeleteSecurityContext(
        IntPtr phContext);

    [DllImport("Secur32.dll", EntryPoint = "EncryptMessage")]
    private static extern Int32 EncryptMessageNative(
        SafeSspiContextHandle phContext,
        UInt32 fQOP,
        ref Helpers.SecBufferDesc pMessage,
        UInt32 MessageSeqNo);

    [DllImport("Secur32.dll")]
    public static extern Int32 FreeContextBuffer(
        IntPtr pvContextBuffer);

    [DllImport("Secur32.dll")]
    public static extern Int32 FreeCredentialsHandle(
        IntPtr phCredential);

    [DllImport("Secur32.dll", CharSet = CharSet.Unicode)]
    private static unsafe extern Int32 InitializeSecurityContextW(
        SafeSspiCredentialHandle phCredential,
        SafeSspiContextHandle phContext,
        [MarshalAs(UnmanagedType.LPWStr)] string pszTargetName,
        InitiatorContextRequestFlags fContextReq,
        UInt32 Reserved1,
        TargetDataRep TargetDataRep,
        Helpers.SecBufferDesc* pInput,
        UInt32 Reserved2,
        SafeSspiContextHandle phNewContext,
        Helpers.SecBufferDesc* pOutput,
        out InitiatorContextReturnFlags pfContextAttr,
        out Helpers.SECURITY_INTEGER ptsExpiry);

    [DllImport("Secur32.dll", EntryPoint = "QueryContextAttributes")]
    private static extern Int32 QueryContextAttributesNative(
        SafeSspiContextHandle phContext,
        SecPkgAttribute ulAttribute,
        IntPtr pBuffer);

    /// <summary>Acquire SSPI credential.</summary>
    /// <param name="principal">The name of the principal whose credentials the handle will reference.</param>
    /// <param name="package">The name of the SSPI security provide the credentials will be used for.</param>
    /// <param name="usage">How the credentials will be used.</param>
    /// <param name="identity">
    /// The credential logon information or <c>null</c> to use the current user's credentials.
    /// </param>
    /// <returns>Credential information including the handle to the credential itself.</returns>
    /// <exception href="SspiException">Error when retrieving the credential.</exception>
    /// <see cref="https://docs.microsoft.com/en-us/windows/win32/secauthn/acquirecredentialshandle--general">AcquireCredentialsHandle</see>
    public static SspiCredential AcquireCredentialsHandle(string? principal, string package, CredentialUse usage,
        WinNTAuthIdentity? identity)
    {
        string? user = identity?.Username;
        string? domain = identity?.Domain;
        string? pass = identity?.Password;

        unsafe
        {
            Helpers.SEC_WINNT_AUTH_IDENTITY_W authData = new();
            Helpers.SEC_WINNT_AUTH_IDENTITY_W* authDataPtr = null;
            fixed (char* userPtr = user, domainPtr = domain, passPtr = pass)
            {
                if (identity != null)
                {
                    authDataPtr = &authData;
                    authData.User = userPtr;
                    authData.UserLength = (UInt16)(identity.Username?.Length ?? 0);
                    authData.Domain = domainPtr;
                    authData.DomainLength = (UInt16)(identity.Domain?.Length ?? 0);
                    authData.Password = passPtr;
                    authData.PasswordLength = (UInt16)(identity.Password?.Length ?? 0);
                    authData.Flags = WinNTAuthIdentityFlags.SEC_WINNT_AUTH_IDENTITY_UNICODE;
                }

                SafeSspiCredentialHandle cred = new();
                int res = AcquireCredentialsHandleW(principal, package, usage, IntPtr.Zero, authDataPtr, IntPtr.Zero,
                    IntPtr.Zero, cred, out var expiryStruct);

                if (res != 0)
                    throw new SspiException(res, "AcquireCredentialsHandle");

                UInt64 expiry = (UInt64)expiryStruct.HighPart << 32 | (UInt64)expiryStruct.LowPart;
                return new SspiCredential(cred, expiry);
            }
        }
    }

    /// <summary>Decrypts the input message.</summary>
    /// <remarks>
    /// The message is decrypted in place, use the input message buffers to retrieve the decrypted value.
    /// </remarks>
    /// <param name="context">The SSPI security context to decrypt the message.</param>
    /// <param name="message">The security buffers to decrypt.</param>
    /// <param name="seqNo">The expected sequence number of the encrypted message.</param>
    /// <returns>The quality of protection that had applied to the encrypted message.</returns>
    /// <exception cref="SspiException">Failure trying to decrypt the message.</exception>
    /// <see href="https://docs.microsoft.com/en-us/windows/win32/secauthn/decryptmessage--general">DecryptMessage</see>
    public static UInt32 DecryptMessage(SafeSspiContextHandle context, Span<Helpers.SecBuffer> message, UInt32 seqNo)
    {
        unsafe
        {
            fixed (Helpers.SecBuffer* messagePtr = message)
            {
                Helpers.SecBufferDesc bufferDesc = new()
                {
                    ulVersion = 0,
                    cBuffers = (UInt32)message.Length,
                    pBuffers = (IntPtr)messagePtr,
                };

                int res = DecryptMessageNative(context, ref bufferDesc, seqNo, out var qop);
                if (res != 0)
                    throw new SspiException(res, "DecryptMessage");

                return qop;
            }
        }
    }

    /// <summary>Encrypts the input message.</summary>
    /// <remarks>
    /// The message is encrypted in place, use the input message buffers to retrieve the encrypted value.
    /// </remarks>
    /// <param name="context">The SSPI security context to encrypt the message.</param>
    /// <param name="qop">The quality of protection to apply to the message.</param>
    /// <param name="message">The security buffers to encrypt.</param>
    /// <param name="seqNo">The sequence number to apply to the encrypted message.</param>
    /// <exception cref="SspiException">Failure trying to entry the message.</exception>
    /// <see href="https://docs.microsoft.com/en-us/windows/win32/secauthn/encryptmessage--general">EncryptMessage</see>
    public static void EncryptMessage(SafeSspiContextHandle context, UInt32 qop, Span<Helpers.SecBuffer> message,
        UInt32 seqNo)
    {
        unsafe
        {
            fixed (Helpers.SecBuffer* messagePtr = message)
            {
                Helpers.SecBufferDesc bufferDesc = new()
                {
                    ulVersion = 0,
                    cBuffers = (UInt32)message.Length,
                    pBuffers = (IntPtr)messagePtr,
                };

                int res = EncryptMessageNative(context, qop, ref bufferDesc, seqNo);
                if (res != 0)
                    throw new SspiException(res, "EncryptMessage");
            }
        }
    }

    /// <summary>Initiates a security context or processes a new token on an existing context.</summary>
    /// <param name="cred">The credential to use for the security context.</param>
    /// <param name="context">
    /// The context handle for the operation. The first call should be set to <c>null</c> while subsequent calls
    /// use the context returned from the first call.
    /// </param>
    /// <param name="targetName">The target name of the acceptor, for Kerberos this is the SPN.</param>
    /// <param name="contextReq">Request flags to set.</param>
    /// <param name="dataRep">The data representation on the target.</param>
    /// <param name="input">Optional token received from the acceptor or null for the first call.</param>
    /// <param name="outputBufferTypes">List of types expected in the output buffer that is returned.</param>
    /// <returns>Context information including the handle to the context itself.</returns>
    /// <exception cref="SspiException">Failure initiating/continuing the security context.</exception>
    /// <see href="https://docs.microsoft.com/en-us/windows/win32/secauthn/initializesecuritycontext--general">InitializeSecurityContext</see>
    public static SspiSecContext InitializeSecurityContext(SafeSspiCredentialHandle cred,
        SafeSspiContextHandle? context, string targetName, InitiatorContextRequestFlags contextReq,
        TargetDataRep dataRep, ReadOnlySpan<Helpers.SecBuffer> input, IList<SecBufferType> outputBufferTypes)
    {
        contextReq |= InitiatorContextRequestFlags.ISC_REQ_ALLOCATE_MEMORY;

        Span<Helpers.SecBuffer> output = stackalloc Helpers.SecBuffer[outputBufferTypes.Count];
        for (int i = 0; i < output.Length; i++)
            output[i].BufferType = (UInt32)outputBufferTypes[i];

        unsafe
        {
            fixed (Helpers.SecBuffer* inputBuffers = input, outputBuffers = output)
            {
                SafeSspiContextHandle inputContext;
                SafeSspiContextHandle outputContext;
                if (context == null)
                {
                    inputContext = SafeSspiContextHandle.NULL_CONTEXT;
                    outputContext = new SafeSspiContextHandle();
                }
                else
                {
                    inputContext = context;
                    outputContext = context;
                }

                Helpers.SecBufferDesc inputBuffer = new();
                Helpers.SecBufferDesc* inputPtr = null;
                if (input.Length > 0)
                {
                    inputBuffer.ulVersion = 0;
                    inputBuffer.cBuffers = (UInt32)input.Length;
                    inputBuffer.pBuffers = (IntPtr)inputBuffers;
                    inputPtr = &inputBuffer;
                }

                Helpers.SecBufferDesc outputBuffer = new();
                Helpers.SecBufferDesc* outputPtr = null;
                if (output.Length > 0)
                {
                    outputBuffer.ulVersion = 0;
                    outputBuffer.cBuffers = (UInt32)output.Length;
                    outputBuffer.pBuffers = (IntPtr)outputBuffers;
                    outputPtr = &outputBuffer;
                }

                int res = InitializeSecurityContextW(cred, inputContext, targetName, contextReq, 0, dataRep,
                    inputPtr, 0, outputContext, outputPtr, out var contextattr, out var expiryStruct);

                if (res != 0 && res != SEC_I_CONTINUE_NEEDED)
                    throw new SspiException(res, "InitializeSecurityContext");

                try
                {
                    bool moreNeeded = res == SEC_I_CONTINUE_NEEDED;
                    UInt64 expiry = (UInt64)expiryStruct.HighPart << 32 | (UInt64)expiryStruct.LowPart;
                    List<byte[]> outputTokens = new();
                    foreach (Helpers.SecBuffer buffer in output)
                    {
                        if (buffer.cbBuffer == 0)
                            continue;

                        byte[] data = new byte[buffer.cbBuffer];
                        Marshal.Copy(buffer.pvBuffer, data, 0, data.Length);
                        outputTokens.Add(data);
                    }

                    return new SspiSecContext(outputContext, outputTokens.ToArray(), expiry, contextattr,
                        moreNeeded);
                }
                finally
                {
                    foreach (Helpers.SecBuffer buffer in output)
                    {
                        if (buffer.pvBuffer != IntPtr.Zero)
                            FreeContextBuffer(buffer.pvBuffer);
                    }
                }
            }
        }
    }

    /// <summary>Query the security context for a specific value.</summary>
    /// <remarks>The buffer supplied must be large enough to fill the requested attribute value.</remarks>
    /// <param name="context">The security context to query.</param>
    /// <param name="attribute">The type of value to query.</param>
    /// <param name="buffer">The buffer that will store the queried value.</param>
    /// <exception cref="SspiException">Failure trying to query the requested value.</exception>
    /// <see href="https://docs.microsoft.com/en-us/windows/win32/secauthn/querycontextattributes--general">QueryContextAttributes</see>
    public static void QueryContextAttributes(SafeSspiContextHandle context, SecPkgAttribute attribute, IntPtr buffer)
    {
        int res = QueryContextAttributesNative(context, attribute, buffer);
        if (res != 0)
            throw new SspiException(res, "QueryContextAttributesNative");
    }
}

public class SspiException : AuthenticationException
{
    public int ErrorCode { get; } = -1;

    public SspiException() { }

    public SspiException(string message) : base(message) { }

    public SspiException(string message, Exception innerException) :
        base(message, innerException)
    { }

    public SspiException(int errorCode, string method)
        : base(GetExceptionMessage(errorCode, method))
    {
        ErrorCode = errorCode;
    }

    private static string GetExceptionMessage(int errorCode, string? method)
    {
        method = String.IsNullOrWhiteSpace(method) ? "SSPI Call" : method;
        string errMsg = new Win32Exception(errorCode).Message;

        return String.Format("{0} failed ({1}, Win32ErrorCode {2} - 0x{2:X8})", method, errMsg, errorCode);
    }
}

/// <summary>User identity information used to acquire a credential handle.</summary>
internal class WinNTAuthIdentity
{
    /// <summary>The username of the identity.</summary>
    public string? Username { get; }

    /// <summary>The domain of the identity.</summary>
    public string? Domain { get; }

    /// <summary>The password of the identity.</summary>
    public string? Password { get; }

    public WinNTAuthIdentity(string? username, string? domain, string? password)
    {
        Username = username;
        Domain = domain;
        Password = password;
    }
}

internal enum CredentialUse : uint
{
    SECPKG_CRED_INBOUND = 0x00000001,
    SECPKG_CRED_OUTBOUND = 0x00000002,
    SECPKG_CRED_BOTH = 0x00000003,
    SECPKG_CRED_DEFAULT = 0x00000004,
    SECPKG_CRED_AUTOLOGON_RESTRICTED = 0x00000010,
    SECPKG_CRED_PROCESS_POLICY_ONLY = 0x00000020,
}

[Flags]
internal enum InitiatorContextRequestFlags : uint
{
    ISC_REQ_DELEGATE = 0x00000001,
    ISC_REQ_MUTUAL_AUTH = 0x00000002,
    ISC_REQ_REPLAY_DETECT = 0x00000004,
    ISC_REQ_SEQUENCE_DETECT = 0x00000008,
    ISC_REQ_CONFIDENTIALITY = 0x00000010,
    ISC_REQ_USE_SESSION_KEY = 0x00000020,
    ISC_REQ_PROMPT_FOR_CREDS = 0x00000040,
    ISC_REQ_USE_SUPPLIED_CREDS = 0x00000080,
    ISC_REQ_ALLOCATE_MEMORY = 0x00000100,
    ISC_REQ_USE_DCE_STYLE = 0x00000200,
    ISC_REQ_DATAGRAM = 0x00000400,
    ISC_REQ_CONNECTION = 0x00000800,
    ISC_REQ_CALL_LEVEL = 0x00001000,
    ISC_REQ_FRAGMENT_SUPPLIED = 0x00002000,
    ISC_REQ_EXTENDED_ERROR = 0x00004000,
    ISC_REQ_STREAM = 0x00008000,
    ISC_REQ_INTEGRITY = 0x00010000,
    ISC_REQ_IDENTIFY = 0x00020000,
    ISC_REQ_NULL_SESSION = 0x00040000,
    ISC_REQ_MANUAL_CRED_VALIDATION = 0x00080000,
    ISC_REQ_RESERVED1 = 0x00100000,
    ISC_REQ_FRAGMENT_TO_FIT = 0x00200000,
    ISC_REQ_FORWARD_CREDENTIALS = 0x00400000,
    ISC_REQ_NO_INTEGRITY = 0x00800000,
    ISC_REQ_USE_HTTP_STYLE = 0x01000000,
    ISC_REQ_UNVERIFIED_TARGET_NAME = 0x20000000,
    ISC_REQ_CONFIDENTIALITY_ONLY = 0x40000000,
}

[Flags]
internal enum InitiatorContextReturnFlags : uint
{
    ISC_RET_DELEGATE = 0x00000001,
    ISC_RET_MUTUAL_AUTH = 0x00000002,
    ISC_RET_REPLAY_DETECT = 0x00000004,
    ISC_RET_SEQUENCE_DETECT = 0x00000008,
    ISC_RET_CONFIDENTIALITY = 0x00000010,
    ISC_RET_USE_SESSION_KEY = 0x00000020,
    ISC_RET_USED_COLLECTED_CREDS = 0x00000040,
    ISC_RET_USED_SUPPLIED_CREDS = 0x00000080,
    ISC_RET_ALLOCATED_MEMORY = 0x00000100,
    ISC_RET_USED_DCE_STYLE = 0x00000200,
    ISC_RET_DATAGRAM = 0x00000400,
    ISC_RET_CONNECTION = 0x00000800,
    ISC_RET_INTERMEDIATE_RETURN = 0x00001000,
    ISC_RET_CALL_LEVEL = 0x00002000,
    ISC_RET_EXTENDED_ERROR = 0x00004000,
    ISC_RET_STREAM = 0x00008000,
    ISC_RET_INTEGRITY = 0x00010000,
    ISC_RET_IDENTIFY = 0x00020000,
    ISC_RET_NULL_SESSION = 0x00040000,
    ISC_RET_MANUAL_CRED_VALIDATION = 0x00080000,
    ISC_RET_RESERVED1 = 0x00100000,
    ISC_RET_FRAGMENT_ONLY = 0x00200000,
    ISC_RET_FORWARD_CREDENTIALS = 0x00400000,
    ISC_RET_USED_HTTP_STYLE = 0x01000000,
    ISC_RET_NO_ADDITIONAL_TOKEN = 0x02000000,
    ISC_RET_REAUTHENTICATION = 0x08000000,
    ISC_RET_CONFIDENTIALITY_ONLY = 0x40000000,
}

internal enum SecBufferFlags : uint
{
    SECBUFFER_READONLY_WITH_CHECKSUM = 0x10000000,
    SECBUFFER_RESERVED = 0x60000000,
    SECBUFFER_READONLY = 0x80000000,
}

internal enum SecBufferType : uint
{
    SECBUFFER_EMPTY = 0,
    SECBUFFER_DATA = 1,
    SECBUFFER_TOKEN = 2,
    SECBUFFER_PKG_PARAMS = 3,
    SECBUFFER_MISSING = 4,
    SECBUFFER_EXTRA = 5,
    SECBUFFER_STREAM_TRAILER = 6,
    SECBUFFER_STREAM_HEADER = 7,
    SECBUFFER_NEGOTIATION_INFO = 8,
    SECBUFFER_PADDING = 9,
    SECBUFFER_STREAM = 10,
    SECBUFFER_MECHLIST = 11,
    SECBUFFER_MECHLIST_SIGNATURE = 12,
    SECBUFFER_TARGET = 13,
    SECBUFFER_CHANNEL_BINDINGS = 14,
    SECBUFFER_CHANGE_PASS_RESPONSE = 15,
    SECBUFFER_TARGET_HOST = 16,
    SECBUFFER_ALERT = 17,
    SECBUFFER_APPLICATION_PROTOCOLS = 18,
    SECBUFFER_SRTP_PROTECTION_PROFILES = 19,
    SECBUFFER_SRTP_MASTER_KEY_IDENTIFIER = 20,
    SECBUFFER_TOKEN_BINDING = 21,
    SECBUFFER_PRESHARED_KEY = 22,
    SECBUFFER_PRESHARED_KEY_IDENTITY = 23,
}

internal enum SecPkgAttribute : uint
{
    SECPKG_ATTR_SIZES = 0,
    SECPKG_ATTR_NAMES = 1,
    SECPKG_ATTR_LIFESPAN = 2,
    SECPKG_ATTR_DCE_INFO = 3,
    SECPKG_ATTR_STREAM_SIZES = 4,
    SECPKG_ATTR_KEY_INFO = 5,
    SECPKG_ATTR_AUTHORITY = 6,
    SECPKG_ATTR_PROTO_INFO = 7,
    SECPKG_ATTR_PASSWORD_EXPIRY = 8,
    SECPKG_ATTR_SESSION_KEY = 9,
    SECPKG_ATTR_PACKAGE_INFO = 10,
    SECPKG_ATTR_USER_FLAGS = 11,
    SECPKG_ATTR_NEGOTIATION_INFO = 12,
    SECPKG_ATTR_NATIVE_NAMES = 13,
    SECPKG_ATTR_FLAGS = 14,
    SECPKG_ATTR_USE_VALIDATED = 15,
    SECPKG_ATTR_CREDENTIAL_NAME = 16,
    SECPKG_ATTR_TARGET_INFORMATION = 17,
    SECPKG_ATTR_ACCESS_TOKEN = 18,
    SECPKG_ATTR_TARGET = 19,
    SECPKG_ATTR_AUTHENTICATION_ID = 20,
    SECPKG_ATTR_LOGOFF_TIME = 21,
    SECPKG_ATTR_NEGO_KEYS = 22,
    SECPKG_ATTR_PROMPTING_NEEDED = 24,
    SECPKG_ATTR_UNIQUE_BINDINGS = 25,
    SECPKG_ATTR_ENDPOINT_BINDINGS = 26,
    SECPKG_ATTR_CLIENT_SPECIFIED_TARGET = 27,
    SECPKG_ATTR_LAST_CLIENT_TOKEN_STATUS = 30,
    SECPKG_ATTR_NEGO_PKG_INFO = 31,
    SECPKG_ATTR_NEGO_STATUS = 32,
    SECPKG_ATTR_CONTEXT_DELETED = 33,
    SECPKG_ATTR_DTLS_MTU = 34,
    SECPKG_ATTR_DATAGRAM_SIZES = SECPKG_ATTR_STREAM_SIZES,
    SECPKG_ATTR_SUBJECT_SECURITY_ATTRIBUTES = 128,
    SECPKG_ATTR_APPLICATION_PROTOCOL = 35,
    SECPKG_ATTR_NEGOTIATED_TLS_EXTENSIONS = 36,
    SECPKG_ATTR_IS_LOOPBACK = 37,
}

internal enum TargetDataRep : uint
{
    SECURITY_NETWORK_DREP = 0x00000000,
    SECURITY_NATIVE_DREP = 0x00000010,
}

internal enum WinNTAuthIdentityFlags : uint
{
    SEC_WINNT_AUTH_IDENTITY_ANSI = 1,
    SEC_WINNT_AUTH_IDENTITY_UNICODE = 2,
}

internal class SafeSspiCredentialHandle : SafeHandle
{
    internal SafeSspiCredentialHandle() : base(Marshal.AllocHGlobal(Marshal.SizeOf<Helpers.SecHandle>()), true) { }

    public override bool IsInvalid => handle == IntPtr.Zero;

    protected override bool ReleaseHandle()
    {
        SSPI.FreeCredentialsHandle(handle);
        Marshal.FreeHGlobal(handle);

        return true;
    }
}

internal class SafeSspiContextHandle : SafeHandle
{
    public static readonly SafeSspiContextHandle NULL_CONTEXT = new(IntPtr.Zero, false);

    internal SafeSspiContextHandle() : base(Marshal.AllocHGlobal(Marshal.SizeOf<Helpers.SecHandle>()), true) { }
    internal SafeSspiContextHandle(IntPtr handle, bool ownsHandle) : base(handle, ownsHandle) { }

    public override bool IsInvalid => handle == IntPtr.Zero;

    protected override bool ReleaseHandle()
    {
        SSPI.DeleteSecurityContext(handle);
        Marshal.FreeHGlobal(handle);

        return true;
    }
}

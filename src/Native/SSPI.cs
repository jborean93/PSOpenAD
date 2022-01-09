using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;

namespace PSOpenAD.Native
{
    internal static partial class Helpers
    {
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct SEC_WINNT_AUTH_IDENTITY_W
        {
            public IntPtr User;
            public UInt32 UserLength;
            public IntPtr Domain;
            public UInt32 DomainLength;
            public IntPtr Password;
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
            UIntPtr dwLower;
            UIntPtr dwUpper;
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

    internal class SspiCredential : IDisposable
    {
        private Helpers.SecHandle _creds;

        public Helpers.SecHandle Creds => _creds;
        public UInt64 Expiry { get; }

        public SspiCredential(Helpers.SecHandle creds, UInt64 expiry)
        {
            _creds = creds;
            Expiry = expiry;
        }

        public void Dispose()
        {
            SSPI.FreeCredentialsHandle(ref _creds);
            GC.SuppressFinalize(this);
        }
        ~SspiCredential() { Dispose(); }
    }

    internal class SspiSecContext : IDisposable
    {
        private Helpers.SecHandle _context;
        public Helpers.SecHandle Context => _context;
        public byte[][] OutputBuffers { get; }
        public UInt64 Expiry { get; }
        public InitiatorContextReturnFlags Flags { get; }
        public bool MoreNeeded { get; }

        public SspiSecContext(Helpers.SecHandle context, byte[][] outputBuffers, UInt64 expiry,
            InitiatorContextReturnFlags flags, bool moreNeeded)
        {
            _context = context;
            OutputBuffers = outputBuffers;
            Expiry = expiry;
            Flags = flags;
            MoreNeeded = moreNeeded;
        }

        public void Dispose()
        {
            SSPI.DeleteSecurityContext(ref _context);
            GC.SuppressFinalize(this);
        }
        ~SspiSecContext() { Dispose(); }
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
            out Helpers.SecHandle phCredential,
            out Helpers.SECURITY_INTEGER ptsExpiry);

        [DllImport("Secur32.dll", EntryPoint = "DecryptMessage")]
        private static extern Int32 DecryptMessageNative(
            ref Helpers.SecHandle phContext,
            ref Helpers.SecBufferDesc pMessage,
            UInt32 MessageSeqNo,
            out UInt32 pfQOP);

        [DllImport("Secur32.dll")]
        public static extern Int32 DeleteSecurityContext(
            ref Helpers.SecHandle phContext);

        [DllImport("Secur32.dll", EntryPoint = "EncryptMessage")]
        private static extern Int32 EncryptMessageNative(
            ref Helpers.SecHandle phContext,
            UInt32 fQOP,
            ref Helpers.SecBufferDesc pMessage,
            UInt32 MessageSeqNo);

        [DllImport("Secur32.dll")]
        public static extern Int32 FreeContextBuffer(
            IntPtr pvContextBuffer);

        [DllImport("Secur32.dll")]
        public static extern Int32 FreeCredentialsHandle(
            ref Helpers.SecHandle phCredential);

        [DllImport("Secur32.dll", CharSet = CharSet.Unicode)]
        private static unsafe extern Int32 InitializeSecurityContextW(
            ref Helpers.SecHandle phCredential,
            Helpers.SecHandle* phContext,
            [MarshalAs(UnmanagedType.LPWStr)] string pszTargetName,
            InitiatorContextRequestFlags fContextReq,
            UInt32 Reserved1,
            TargetDataRep TargetDataRep,
            Helpers.SecBufferDesc* pInput,
            UInt32 Reserved2,
            out Helpers.SecHandle phNewContext,
            Helpers.SecBufferDesc* pOutput,
            out InitiatorContextReturnFlags pfContextAttr,
            out Helpers.SECURITY_INTEGER ptsExpiry);

        [DllImport("Secur32.dll", EntryPoint = "QueryContextAttributes")]
        private static extern Int32 QueryContextAttributesNative(
            ref Helpers.SecHandle phContext,
            SecPkgAttribute ulAttribute,
            IntPtr pBuffer);

        public static SspiCredential AcquireCredentialsHandle(string? principal, string package, CredentialUse usage,
            WinNTAuthIdentity? identity)
        {
            byte[]? user = null;
            byte[]? domain = null;
            byte[]? pass = null;

            unsafe
            {
                Helpers.SEC_WINNT_AUTH_IDENTITY_W* authData = null;
                if (identity != null)
                {
                    user = identity.Username == null ? null : Encoding.UTF8.GetBytes(identity.Username);
                    domain = identity.Domain == null ? null : Encoding.UTF8.GetBytes(identity.Domain);
                    pass = identity.Password == null ? null : Encoding.UTF8.GetBytes(identity.Password);
                }

                fixed (byte* userPtr = user, domainPtr = domain, passPtr = pass)
                {
                    if (identity != null)
                    {
                        authData->User = (IntPtr)userPtr;
                        authData->UserLength = (UInt16)(identity.Username?.Length ?? 0);
                        authData->Domain = (IntPtr)domainPtr;
                        authData->DomainLength = (UInt16)(identity.Domain?.Length ?? 0);
                        authData->Password = (IntPtr)passPtr;
                        authData->PasswordLength = (UInt16)(identity.Password?.Length ?? 0);
                    }

                    int res = AcquireCredentialsHandleW(principal, package, usage, IntPtr.Zero, authData, IntPtr.Zero,
                        IntPtr.Zero, out var cred, out var expiryStruct);

                    if (res != 0)
                        throw new Win32Exception(res);

                    UInt64 expiry = (UInt64)expiryStruct.HighPart << 32 | (UInt64)expiryStruct.LowPart;
                    return new SspiCredential(cred, expiry);
                }
            }
        }

        public static UInt32 DecryptMessage(SspiSecContext context, Span<Helpers.SecBuffer> message, UInt32 seqNo)
        {
            Helpers.SecHandle secHandle = context.Context;

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

                    int res = DecryptMessageNative(ref secHandle, ref bufferDesc, seqNo, out var qop);
                    if (res != 0)
                        throw new Win32Exception(res);

                    return qop;
                }
            }
        }

        public static void EncryptMessage(SspiSecContext context, UInt32 qop, Span<Helpers.SecBuffer> message,
            UInt32 seqNo)
        {
            Helpers.SecHandle secHandle = context.Context;

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

                    int res = EncryptMessageNative(ref secHandle, qop, ref bufferDesc, seqNo);
                    if (res != 0)
                        throw new Win32Exception(res);
                }
            }
        }

        public static SspiSecContext InitializeSecurityContext(SspiCredential cred, SspiSecContext? context,
            string targetName, InitiatorContextRequestFlags contextReq, TargetDataRep dataRep,
            ReadOnlySpan<Helpers.SecBuffer> input, IList<SecBufferType> outputBufferTypes)
        {
            Helpers.SecHandle credential = cred.Creds;
            contextReq |= InitiatorContextRequestFlags.ISC_REQ_ALLOCATE_MEMORY;

            Span<Helpers.SecBuffer> output = stackalloc Helpers.SecBuffer[outputBufferTypes.Count];
            for (int i = 0; i < output.Length; i++)
                output[i].BufferType = (UInt32)outputBufferTypes[i];

            unsafe
            {
                fixed (Helpers.SecBuffer* inputBuffers = input, outputBuffers = output)
                {
                    Helpers.SecHandle inputContext;
                    Helpers.SecHandle* inputContextPtr = null;
                    if (context != null)
                    {
                        inputContext = context.Context;
                        inputContextPtr = &inputContext;
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

                    int res = InitializeSecurityContextW(ref credential, inputContextPtr, targetName, contextReq, 0,
                        dataRep, inputPtr, 0, out var newContext, outputPtr, out var contextattr,
                        out var expiryStruct);

                    if (res != 0 && res != SEC_I_CONTINUE_NEEDED)
                        throw new Win32Exception(res);

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

                        return new SspiSecContext(newContext, outputTokens.ToArray(), expiry, contextattr,
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

        public static void QueryContextAttributes(SspiSecContext context, SecPkgAttribute attribute, IntPtr buffer)
        {
            Helpers.SecHandle contextHandle = context.Context;
            int res = QueryContextAttributesNative(ref contextHandle, attribute, buffer);
            if (res != 0)
                throw new Win32Exception(res);
        }
    }

    internal class WinNTAuthIdentity
    {
        public string? Username { get; }
        public string? Domain { get; }
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

    internal class SafeSspiBuffer : SafeHandle
    {
        internal SafeSspiBuffer() : base(IntPtr.Zero, true) { }

        public override bool IsInvalid => handle == IntPtr.Zero;

        protected override bool ReleaseHandle()
        {
            return SSPI.FreeContextBuffer(handle) == 0;
        }
    }
}

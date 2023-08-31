using System;
using System.ComponentModel;
using System.Runtime.InteropServices;

namespace PSOpenAD.Native;

internal static partial class Helpers
{
    [StructLayout(LayoutKind.Sequential)]
    public struct DOMAIN_CONTROLLER_INFOW
    {
        public IntPtr DomainControllerName;
        public IntPtr DomainControllerAddress;
        public DCAddressType DomainControllerAddressType;
        public Guid DomainGuid;
        public IntPtr DomainName;
        public IntPtr DnsForestName;
        public DCFlags Flags;
        public IntPtr DcSiteName;
        public IntPtr ClientSiteName;
    }
}

internal static class NetApi32
{
    [DllImport("NetApi32.dll", CharSet = CharSet.Unicode)]
    private static unsafe extern Int32 DsGetDcNameW(
        string? ComputerName,
        string? DomainName,
        Guid?* DomainGuid,
        string? SiteName,
        GetDcFlags Flags,
        out SafeNetApiBuffer DomainControllerInfo);

    [DllImport("NetApi32.dll")]
    public static extern Int32 NetApiBufferFree(
        IntPtr Buffer);

    public static DCInfo DsGetDcName(string? domainName, string? computerName = null, string? siteName = null,
        GetDcFlags flags = GetDcFlags.None, Guid? domainGuid = null)
    {
        unsafe
        {
            Guid?* domainGuidPtr = &domainGuid;
            Int32 res = DsGetDcNameW(computerName, domainName, domainGuidPtr, siteName, flags, out var rawInfo);
            if (res != 0)
                throw new Win32Exception(res);

            using (rawInfo)
            {
                var info = (Helpers.DOMAIN_CONTROLLER_INFOW*)rawInfo.DangerousGetHandle().ToPointer();

                return new DCInfo()
                {
                    Name = Marshal.PtrToStringUni(info->DomainControllerName),
                    Address = Marshal.PtrToStringUni(info->DomainControllerAddress),
                    AddressType = info->DomainControllerAddressType,
                    DomainGuid = info->DomainGuid,
                    DomainName = Marshal.PtrToStringUni(info->DomainName),
                    DnsForestName = Marshal.PtrToStringUni(info->DnsForestName),
                    Flags = info->Flags,
                    DcSiteName = Marshal.PtrToStringUni(info->DcSiteName),
                    ClientSiteName = Marshal.PtrToStringUni(info->ClientSiteName),
                };
            }
        }
    }
}

public class DCInfo
{
    public string? Name { get; internal set; }
    public string? Address { get; internal set; }
    public DCAddressType AddressType { get; internal set; }
    public Guid DomainGuid { get; internal set; }
    public string? DomainName { get; internal set; }
    public string? DnsForestName { get; internal set; }
    public DCFlags Flags { get; internal set; }
    public string? DcSiteName { get; internal set; }
    public string? ClientSiteName { get; internal set; }
}

public enum DCAddressType : uint
{
    DS_INET_ADDRESS = 1,
    DS_NETBIOS_ADDRESS = 2,
}

[Flags]
public enum DCFlags : uint
{
    DS_PDC_FLAG = 0x00000001,
    DS_GC_FLAG = 0x00000004,
    DS_LDAP_FLAG = 0x00000008,
    DS_DS_FLAG = 0x00000010,
    DS_KDC_FLAG = 0x00000020,
    DS_TIMESERV_FLAG = 0x00000040,
    DS_CLOSEST_FLAG = 0x00000080,
    DS_WRITABLE_FLAG = 0x00000100,
    DS_GOOD_TIMESERV_FLAG = 0x00000200,
    DS_NDNC_FLAG = 0x00000400,
    DS_SELECT_SECRET_DOMAIN_6_FLAG = 0x00000800,
    DS_FULL_SECRET_DOMAIN_6_FLAG = 0x00001000,
    DS_WS_FLAG = 0x00002000,
    DS_DS_8_FLAG = 0x00004000,
    DS_DS_9_FLAG = 0x00008000,
    DS_DS_10_FLAG = 0x00010000,
    DS_PING_FLAGS = 0x000FFFFF,
    DS_DNS_CONTROLLER_FLAG = 0x20000000,
    DS_DNS_DOMAIN_FLAG = 0x40000000,
    DS_DNS_FOREST_FLAG = 0x80000000,
}

[Flags]
public enum GetDcFlags : uint
{
    None = 0x00000000,
    DS_FORCE_REDISCOVERY = 0x00000001,
    DS_DIRECTORY_SERVICE_REQUIRED = 0x00000010,
    DS_DIRECTORY_SERVICE_PREFERRED = 0x00000020,
    DS_GC_SERVER_REQUIRED = 0x00000040,
    DS_PDC_REQUIRED = 0x00000080,
    DS_BACKGROUND_ONLY = 0x00000100,
    DS_IP_REQUIRED = 0x00000200,
    DS_KDC_REQUIRED = 0x00000400,
    DS_TIMESERV_REQUIRED = 0x00000800,
    DS_WRITABLE_REQUIRED = 0x00001000,
    DS_GOOD_TIMESERV_PREFERRED = 0x00002000,
    DS_AVOID_SELF = 0x00004000,
    DS_ONLY_LDAP_NEEDED = 0x00008000,
    DS_IS_FLAT_NAME = 0x00010000,
    DS_IS_DNS_NAME = 0x00020000,
    DS_TRY_NEXTCLOSEST_SITE = 0x00040000,
    DS_DIRECTORY_SERVICE_6_REQUIRED = 0x00080000,
    DS_WEB_SERVICE_REQUIRED = 0x00100000,
    DS_DIRECTORY_SERVICE_8_REQUIRED = 0x00200000,
    DS_DIRECTORY_SERVICE_9_REQUIRED = 0x00400000,
    DS_DIRECTORY_SERVICE_10_REQUIRED = 0x00800000,
    DS_RETURN_DNS_NAME = 0x40000000,
    DS_RETURN_FLAT_NAME = 0x80000000,
}

internal class SafeNetApiBuffer : SafeHandle
{
    internal SafeNetApiBuffer() : base(IntPtr.Zero, true) { }
    public override bool IsInvalid => handle == IntPtr.Zero;

    protected override bool ReleaseHandle()
    {
        return NetApi32.NetApiBufferFree(handle) == 0;
    }
}

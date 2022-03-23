#!powershell

# Copyright: (c) 2022 Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

#AnsibleRequires -CSharpUtil Ansible.Basic

$spec = @{
    options             = @{
        dns_domain_name       = @{ type = 'str' }
        domain_admin_password = @{ type = 'str'; required = $true; no_log = $true }
        domain_admin_username = @{ type = 'str'; required = $true }
        site_name             = @{ type = 'str' }
        safe_mode_password    = @{ type = 'str'; no_log = $true }
    }
    required_together   = @(
        , @("domain_admin_username", "domain_admin_password")
    )
    supports_check_mode = $true
}
$module = [Ansible.Basic.AnsibleModule]::Create($args, $spec)

$dnsDomainName = $module.Params.dns_domain_name
$domainAdminUserName = $module.Params.domain_admin_username
$domainAdminPassword = $module.Params.domain_admin_password
$safeModePassword = $module.Params.safe_mode_password
$siteName = $module.Params.site_name

$module.Result.reboot_required = $false

$systemRole = Get-CimInstance -ClassName Win32_ComputerSystem -Property Domain, DomainRole
if ($systemRole.DomainRole -in @(4, 5)) {
    if ($systemRole.Domain -ne $dnsDomainName) {
        $module.FailJson("Host is already a domain controller in another domain $($systemRole.Domain)")
    }
    $module.ExitJson()
}

$newDomainName, $parentDomainName = $dnsDomainName.Split(".", 2)

$cred = New-Object -TypeName PSCredential -ArgumentList @(
    $domainAdminUserName,
    (ConvertTo-SecureString -AsPlainText -Force -String $domainAdminPassword)
)
$installParams = @{
    NewDomainName                 = $newDomainName
    ParentDomainName              = $parentDomainName
    DomainMode                    = 'WinThreshold'
    DomainType                    = 'ChildDomain'
    NoRebootOnCompletion          = $true
    SafeModeAdministratorPassword = (ConvertTo-SecureString -AsPlainText -Force -String $safeModePassword)
    Force                         = $true
    Credential                    = $cred
    WhatIf                        = $module.CheckMode
}
if ($siteName) {
    $installParams.SiteName = $siteName
}

$res = $null
try {
    $res = Install-ADDSDomain @installParams
}
catch {
    # ExitCode 15 == 'Role change is in progress or this computer needs to be restarted.'
    # DCPromo exit codes details can be found at
    # https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/deploy/troubleshooting-domain-controller-deployment
    if ($_.Exception.ErrorCode -in @(15, 19)) {
        $module.Result.reboot_required = $true
    }
    else {
        $module.FailJson("Failed to install ADDSDomain, DCPromo exited with $($_.Exception.ExitCode)", $_)
    }
}

$module.Result.changed = $true

if ($module.CheckMode) {
    $module.Result.reboot_required = $true
}
elseif ($res) {
    $module.Result.reboot_required = $res.RebootRequired

    # The Netlogon service is set to auto start but is not started. This is
    # required for Ansible to connect back to the host and reboot in a
    # later task. Even if this fails Ansible can still connect but only
    # with ansible_winrm_transport=basic so we just display a warning if
    # this fails.
    try {
        Start-Service -Name Netlogon
    }
    catch {
        $msg = -join @(
            "Failed to start the Netlogon service after promoting the host, "
            "Ansible may be unable to connect until the host is manually rebooting: $($_.Exception.Message)"
        )
        $module.Warn($msg)
    }
}

$module.ExitJson()

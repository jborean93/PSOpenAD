#!/bin/bash

lib::setup::system_requirements() {
    if [ x"${GITHUB_ACTIONS}" = "xtrue" ]; then
        echo "::group::Setting up System Packages"
    fi

    if [ -f /etc/redhat-release ]; then
        lib::setup::system_requirements::el

    else
        echo "Distro not found!"
        false

    fi

    if [ x"${GITHUB_ACTIONS}" = "xtrue" ]; then
        echo "::endgroup::"
    fi
}

lib::setup::system_requirements::el() {
    rpm -Uvh https://packages.microsoft.com/config/rhel/8/packages-microsoft-prod.rpm

    # krb5-libs - Provides the MIT GSSAPI/Krb5 Library
    # krb5-workstation - Provides kinit for tests but not needed by PSOpenAD
    dnf install -y \
        --nogpgcheck \
        --disablerepo=\*modul\* \
        krb5-libs \
        krb5-workstation \
        dotnet-runtime-3.0 \
        dotnet-sdk-6.0 \
        powershell

    export PATH="~/.dotnet/tools:$PATH"
}

lib::setup::gssapi() {
    # Wait for the DC to have been created and is ready for connections
    pwsh -NoProfile -NoLogo -File ./tools/WaitSocket.ps1 -TargetHost dc.psopenad.test -Port 389 -Timeout 60000

    cat > /tmp/psopenad-krb5.conf << EOF
[libdefaults]
  rdns = no
  default_realm = ${AD_REALM^^}

[realms]
    ${AD_REALM^^} = {
        kdc = dc.${AD_REALM,,}
    }

[domain_realm]
  ${AD_REALM,,} = ${AD_REALM^^}
  .${AD_REALM,,} = ${AD_REALM^^}
EOF

    export KRB5_CONFIG="/tmp/psopenad-krb5.conf"
    export KRB5CCNAME="DIR:/tmp/ccache-dir"

    echo "Getting Kerberos ticket for primary user"
    echo "${AD_PASSWORD}" | kinit "Administrator@${AD_REALM^^}"
    klist -l
}

lib::tests::run() {
    if [ x"${GITHUB_ACTIONS}" = "xtrue" ]; then
        echo "::group::Running Tests"
    fi

    pwsh -NoProfile -NoLogo -Command - << EOF
\$ErrorActionPreference = 'Stop'

ConvertTo-Json -InputObject ([Ordered]@{
    server = 'dc.${AD_REALM,,}'
    credentials = @(
        [Ordered]@{
            username = 'Administrators@${AD_REALM^^}'
            password = '${AD_PASSWORD}'
            cached = \$true
        }
    )
    tls = [Ordered]@{
        trusted = \$true
    }
    features = [Ordered]@{
        negotiate_auth = \$true
    }
}) | Out-File ./test.settings.json

exit
EOF

    pwsh -File ./build.ps1 -Configuration "${BUILD_CONFIGURATION:-Debug}" -Task Build
    pwsh -File ./build.ps1 -Configuration "${BUILD_CONFIGURATION:-Debug}" -Task Test

    if [ x"${GITHUB_ACTIONS}" = "xtrue" ]; then
        echo "::endgroup::"
    fi
}

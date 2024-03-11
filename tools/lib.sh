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

    if [ x"${GSSAPI_PROVIDER}" = "xheimdal" ]; then
        # heimdal-libs - Provides the Heimdal GSSAPI/Krb5 Library
        # heimdal-path - Ensures the Heimdal libs come first in the PATH
        # heimdal-workstation - Provides kinit for tests but not needed by PSOpenAD
        dnf install -y \
            --nogpgcheck \
            --disablerepo=\*modul\* \
            heimdal-libs \
            heimdal-path \
            heimdal-workstation \
            dotnet-sdk-6.0 \
            wget

        source /etc/profile.d/heimdal.sh

        # Ugly hack but we can't uninstall MIT krb5 so to ensure our tests test
        # against Heimdal we rename the MIT krb5 libs.
        mv /lib64/libgssapi_krb5.so.2 /lib64/libgssapi_krb5.so.2.bak
        mv /lib64/libgssapi_krb5.so.2.2 /lib64/libgssapi_krb5.so.2.2.bak
        mv /lib64/libkrb5.so.3 /lib64/libkrb5.so.3.bak
        mv /lib64/libkrb5.so.3.3 /lib64/libkrb5.so.3.3.bak

    else
        # krb5-libs - Provides the MIT GSSAPI/Krb5 Library
        # krb5-workstation - Provides kinit for tests but not needed by PSOpenAD
        dnf install -y \
            --nogpgcheck \
            --disablerepo=\*modul\* \
            krb5-libs \
            krb5-workstation \
            dotnet-sdk-6.0 \
            wget
    fi

    mkdir "/tmp/PowerShell-${PWSH_VERSION}"
    echo "Downloading PowerShell ${PWSH_VERSION}"
    wget \
        --quiet \
        --output-document "/tmp/powershell.tar.gz" \
        "https://github.com/PowerShell/PowerShell/releases/download/v${PWSH_VERSION}/powershell-${PWSH_VERSION}-linux-x64.tar.gz"

    echo "Extracting PowerShell ${PWSH_VERSION}"
    tar xf \
        "/tmp/powershell.tar.gz" \
        --directory "/tmp/PowerShell-${PWSH_VERSION}"
    chmod +x "/tmp/PowerShell-${PWSH_VERSION}/pwsh"

    export PATH="/tmp/PowerShell-${PWSH_VERSION}:~/.dotnet/tools:${PATH}"
}

lib::setup::gssapi() {
    cat > /tmp/psopenad-krb5.conf << EOF
[libdefaults]
  rdns = false
  default_realm = ${AD_REALM^^}
EOF

    export KRB5_CONFIG="/tmp/psopenad-krb5.conf"

    echo "Getting Kerberos ticket for primary user"
    if [ x"${GSSAPI_PROVIDER}" = "xheimdal" ]; then
        echo "${AD_PASSWORD}" | kinit --password-file=STDIN "Administrator@${AD_REALM^^}"
        klist

    else
        export KRB5CCNAME="DIR:/tmp/ccache-dir"
        echo "${AD_PASSWORD}" | kinit "Administrator@${AD_REALM^^}"
        klist -l
    fi
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
            username = 'Administrator@${AD_REALM^^}'
            password = '${AD_PASSWORD}'
            cached = \$true
        }
    )
    tls = [Ordered]@{
        trusted = \$false
    }
    features = [Ordered]@{
        negotiate_auth = \$true
        implicit_server = \$true
    }
}) | Out-File ./test.settings.json

exit
EOF

    pwsh -File ./build.ps1 \
        -Configuration "${BUILD_CONFIGURATION:-Debug}" \
        -Task Test \
        -ModuleNupkg output/*.nupkg

    if [ x"${GITHUB_ACTIONS}" = "xtrue" ]; then
        echo "::endgroup::"
    fi
}

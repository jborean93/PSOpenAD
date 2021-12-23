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

    dnf install -y \
        --nogpgcheck \
        --disablerepo=\*modul\* \
        dotnet-sdk-5.0 \
        powershell

    export PATH="~/.dotnet/tools:$PATH"
}

lib::tests::run() {
    if [ x"${GITHUB_ACTIONS}" = "xtrue" ]; then
        echo "::group::Running Tests"
    fi

    # TODO: Figure out a way to check the DC is online, the Docker network seems to accept the connection even if it's
    # not online yet.
    # pwsh -NoProfile -NoLogo -File ./tools/WaitSocket.ps1 -TargetHost dc.psopenad.test -Port 389 -Timeout 60000

    pwsh -File ./build.ps1 -Configuration "${BUILD_CONFIGURATION:-Debug}" -Task Test

    if [ x"${GITHUB_ACTIONS}" = "xtrue" ]; then
        echo "::endgroup::"
    fi
}

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
    dnf install -y \
        --nogpgcheck \
        gcc \
        epel-release

    if [ x"${GSSAPI_PROVIDER}" = "xheimdal" ]; then
        # heimdal-libs - Provides the Heimdal GSSAPI/Krb5 Library
        # heimdal-path - Ensures the Heimdal libs come first in the PATH
        # heimdal-workstation - Provides kinit for tests but not needed by PSOpenAD
        dnf install -y \
            --nogpgcheck \
            heimdal-libs \
            heimdal-path \
            heimdal-workstation \
            dotnet-sdk-9.0

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
            krb5-libs \
            krb5-workstation \
            dotnet-sdk-9.0
    fi

    # We don't care about the version for the initial bootstrap script, it'll handle
    # the installation of the correct version when testing.
    dotnet tool install --global PowerShell
    export PATH="$PATH:~/.dotnet/tools"

    # Unit tests might run on a different version than the SDK that is installed
    # this allows it to rull forward to the earliest major version available.
    export DOTNET_ROLL_FORWARD=Major

    # A test relies on being able to control the hostname returned by gethostname.
    # This generates a shim that will return the desired test value before falling
    # back to the libc call if unset.
    cat > /tmp/gethostname.c << EOF
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dlfcn.h>
#include <errno.h>

static int (*real_gethostname)(char *, size_t) = NULL;

int gethostname(char *name, size_t len) {
    const char *mock_hostname = getenv("_PSOPENAD_MOCK_HOSTNAME");
    if (mock_hostname) {
        size_t mock_len = strlen(mock_hostname);
        if (mock_len >= len) {
            errno = ENAMETOOLONG;
            return -1;
        }

        strncpy(name, mock_hostname, len - 1);
        name[len - 1] = '\0';  // Ensure null termination
        return 0;
    }

    if (!real_gethostname) {
        real_gethostname = dlsym(RTLD_NEXT, "gethostname");
        if (!real_gethostname) {
            fprintf(stderr, "Error loading original gethostname: %s\n", dlerror());
            return -1;
        }
    }

    return real_gethostname(name, len);
}
EOF
    echo "Compiling gethostname shim"
    gcc \
        -fPIC -rdynamic -g -Wall -shared -Wl,-soname,libgethostnameshim.so.1 -lc -ldl \
        -o /usr/lib64/libgethostnameshim.so.1 \
        /tmp/gethostname.c
    export LD_PRELOAD=/usr/lib64/libgethostnameshim.so.1
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

    cat > "./test.settings.json" << EOF
{
  "server": "dc.${AD_REALM,,}",
  "credentials": [
    {
      "username": "Administrator@${AD_REALM^^}",
      "password": "${AD_PASSWORD}",
      "cached": true
    }
  ],
  "tls": {
    "trusted": false
  },
  "features": {
    "negotiate_auth": true,
    "implicit_server": true
  }
}
EOF

    pwsh -File ./build.ps1 \
        -Configuration "${BUILD_CONFIGURATION:-Debug}" \
        -Task Test \
        -PowerShellVersion "${PWSH_VERSION:-7.4}" \
        -ModuleNupkg output/*.nupkg

    if [ x"${GITHUB_ACTIONS}" = "xtrue" ]; then
        echo "::endgroup::"
    fi
}

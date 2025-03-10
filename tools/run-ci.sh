#!/bin/bash -e

IMAGE=${1}
if [[ -z "${IMAGE}" ]]; then
    echo "Must provide docker image to use for the test as the first argument" 1>&2
    exit 1
fi

GSSAPI_PROVIDER=${2}
if [[ -z "${GSSAPI_PROVIDER}" ]]; then
    echo "Must provide GSSAPI provider [mit|heimdal] use for the test as the second argument" 1>&2
    exit 1
fi

BUILD_CONFIGURATION=${3}
if [[ -z "${BUILD_CONFIGURATION}" ]]; then
    echo "Must provide build configuration (Debug|Release) as the third argument" 1>&2
    exit 1
fi

PWSH_VERSION=${4}
if [[ -z "${PWSH_VERSION}" ]]; then
    echo "Must provider a pwsh version as the fourth argument" 1>&2
    exit 1
fi

REALM=${AD_REALM:-PSOPENAD.TEST}
PASSWORD=${AD_PASSWORD:-Password01}
NETWORK_NAME=psopenad-net-$( openssl rand -hex 5 )
DC_CONTAINER_ID=""

if [ x"${GITHUB_ACTIONS}" = "xtrue" ]; then
    DOCKER_BIN=docker
elif [ -x "$( command -v podman )" ]; then
    DOCKER_BIN=podman
else
    DOCKER_BIN=docker
fi

VOLUME_FLAGS=""
if [ -x "$( command -v getenforce )" ] && [ "$( getenforce | xargs )" == "Enforcing" ]; then
    VOLUME_FLAGS=":z"
fi

function cleanup()
{
    if [ "$( $DOCKER_BIN ps -q -f id=${DC_CONTAINER_ID} )" ]; then
        $DOCKER_BIN kill "${DC_CONTAINER_ID}" >/dev/null 2>&1
    fi

    $DOCKER_BIN network inspect "${NETWORK_NAME}" >/dev/null 2>&1 && \
      $DOCKER_BIN network rm "${NETWORK_NAME}" >/dev/null 2>&1
}
trap cleanup EXIT

$DOCKER_BIN network inspect "${NETWORK_NAME}" >/dev/null 2>&1 || \
    $DOCKER_BIN network create --driver bridge "${NETWORK_NAME}"

echo "Starting Samba DC container"
DC_CONTAINER_ID=$( $DOCKER_BIN run \
    --detach \
    --rm \
    --volume "$( pwd ):/tmp/PSOpenAD${VOLUME_FLAGS}" \
    --env AD_REALM="${REALM^^}" \
    --env AD_PASSWORD="${PASSWORD}" \
    --hostname "dc.${REALM,,}" \
    --network "${NETWORK_NAME}" \
    --network-alias dc \
    --network-alias "dc.${REALM,,}" \
    debian:12 /bin/bash /tmp/PSOpenAD/tools/setup-samba.sh )

echo "Getting Samba DC container IP"
DC_IP=$( $DOCKER_BIN inspect -f \
    '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' \
    "${DC_CONTAINER_ID}"
)

echo "Waiting for Samba to come online"
$DOCKER_BIN exec \
    "${DC_CONTAINER_ID}" \
    /bin/bash -c "until pidof samba >/dev/null 2>&1; do sleep 1; done"

echo "Starting test container"
$DOCKER_BIN run \
  --rm \
  --interactive \
  --volume "$( pwd ):/tmp/PSOpenAD${VOLUME_FLAGS}" \
  --workdir /tmp/PSOpenAD \
  --env AD_REALM="${REALM^^}" \
  --env AD_PASSWORD="${PASSWORD}" \
  --env GSSAPI_PROVIDER="${GSSAPI_PROVIDER}" \
  --env BUILD_CONFIGURATION="${BUILD_CONFIGURATION}" \
  --env PWSH_VERSION="${PWSH_VERSION}" \
  --env GITHUB_ACTIONS="${GITHUB_ACTIONS:-false}" \
  --env DOTNET_CLI_TELEMETRY_OPTOUT=1 \
  --env POWERSHELL_TELEMETRY_OPTOUT=1 \
  --env DOTNET_SKIP_FIRST_TIME_EXPERIENCE=1 \
  --env DOTNET_NOLOGO=1 \
  --hostname "app.${REALM,,}" \
  --network "${NETWORK_NAME}" \
  --network-alias app \
  --network-alias "app.${REALM,,}" \
  --dns "${DC_IP}" \
  "${IMAGE}" /bin/bash -e -c 'source /dev/stdin' << 'EOF'

source ./tools/lib.sh

lib::setup::system_requirements
lib::setup::gssapi
lib::tests::run
EOF

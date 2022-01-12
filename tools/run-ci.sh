#!/bin/bash -e

IMAGE=${1}
if [[ -z "${IMAGE}" ]]; then
    echo "Must provide docker image to use for the test as first argument" 1>&2
    exit 1
fi

BUILD_CONFIGURATION=${2}
if [[ -z "${BUILD_CONFIGURATION}" ]]; then
    echo "Must provide build configuration (Debug|Release) as first argument" 1>&2
    exit 1
fi

REALM=${AD_REALM:-PSOPENAD.TEST}
PASSWORD=${AD_PASSWORD:-Password01}
NETWORK_NAME=psopenad-net-$( openssl rand -hex 5 )
DC_CONTAINER_ID=""

if [ -x "$( command -v podman )" ]; then
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
        $DOCKER_BIN kill "${DC_CONTAINER_ID}"
    fi

    $DOCKER_BIN network inspect "${NETWORK_NAME}" >/dev/null 2>&1 && \
      $DOCKER_BIN network rm "${NETWORK_NAME}"
}
trap cleanup EXIT

$DOCKER_BIN network inspect "${NETWORK_NAME}" >/dev/null 2>&1 || \
    $DOCKER_BIN network create --driver bridge "${NETWORK_NAME}"

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
    debian:11 /bin/bash /tmp/PSOpenAD/tools/setup-samba.sh )

$DOCKER_BIN run \
  --rm \
  --interactive \
  --volume "$( pwd ):/tmp/PSOpenAD${VOLUME_FLAGS}" \
  --workdir /tmp/PSOpenAD \
  --env AD_REALM="${REALM^^}" \
  --env AD_PASSWORD="${PASSWORD}" \
  --env BUILD_CONFIGURATION="${BUILD_CONFIGURATION}" \
  --hostname "app.${REALM,,}" \
  --network "${NETWORK_NAME}" \
  --network-alias app \
  --network-alias "app.${REALM,,}" \
  "${IMAGE}" /bin/bash -e -c 'source /dev/stdin' << 'EOF'

source ./tools/lib.sh

lib::setup::system_requirements
lib::setup::gssapi
lib::tests::run
EOF

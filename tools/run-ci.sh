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

function cleanup()
{
    if [ "$(docker ps -q -f name=psopenad_dc)" ]; then
        docker kill psopenad_dc
    fi

    docker network inspect psopenad-net >/dev/null 2>&1 && \
      docker network rm psopenad-net
}
trap cleanup EXIT

docker network inspect psopenad-net >/dev/null 2>&1 || \
    docker network create --driver bridge psopenad-net

docker run \
    --detach \
    --rm \
    --volume "$( pwd )":/tmp/PSOpenAD:z \
    --env AD_REALM="${REALM^^}" \
    --env AD_PASSWORD="${PASSWORD}" \
    --name psopenad_dc \
    --hostname "dc.${REALM,,}" \
    --net psopenad-net \
    --cap-add SYS_ADMIN \
    debian:11 /bin/bash /tmp/PSOpenAD/tools/setup-samba.sh

docker run \
  --rm \
  --interactive \
  --volume "$( pwd )":/tmp/PSOpenAD:z \
  --workdir /tmp/PSOpenAD \
  --env AD_REALM="${REALM^^}" \
  --env AD_PASSWORD="${PASSWORD}" \
  --env BUILD_CONFIGURATION="${BUILD_CONFIGURATION}" \
  --name psopenad_app \
  --hostname "dc.${REALM,,}" \
  --net psopenad-net \
  "${IMAGE}" /bin/bash -ex -c 'source /dev/stdin' << 'EOF'

source ./tools/lib.sh

lib::setup::system_requirements
lib::tests::run
EOF

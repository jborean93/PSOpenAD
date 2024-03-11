#!/bin/bash -e

REALM=${AD_REALM:-PSOPENAD.TEST}
PASSWORD=${AD_PASSWORD:-Password01}
ROOT_DIR=$( dirname $( dirname $( readlink -fm $0 ) ) )

if [ -x "$( command -v podman )" ]; then
    DOCKER_BIN=podman
else
    DOCKER_BIN=docker
fi

VOLUME_FLAGS=""
if [ -x "$( command -v getenforce )" ] && [ "$( getenforce | xargs )" == "Enforcing" ]; then
    VOLUME_FLAGS=":z"
fi

cat > "${ROOT_DIR}/test.settings.json" << EOF
{
  "server": "localhost",
  "port": 8389,
  "credentials": [
    {
      "username": "Administrator@${REALM^^}",
      "password": "${PASSWORD}",
      "cached": false
    }
  ],
  "tls": {
    "trusted": false,
    "port": 8636
  }
}
EOF

echo "Starting Samba DC container"
$DOCKER_BIN run \
    --rm \
    --volume "${ROOT_DIR}:/tmp/PSOpenAD${VOLUME_FLAGS}" \
    --env AD_REALM="${REALM^^}" \
    --env AD_PASSWORD="${PASSWORD}" \
    --hostname "dc.${REALM,,}" \
    --publish 8389:389 \
    --publish 8636:636 \
    debian:12 /bin/bash /tmp/PSOpenAD/tools/setup-samba.sh

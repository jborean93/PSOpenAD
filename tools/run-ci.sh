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
DC_LOGS_PID=""
DC_STARTUP_TIMEOUT=${DC_STARTUP_TIMEOUT:-120}

if [ x"${GITHUB_ACTIONS}" = "xtrue" ]; then
    # DOCKER_BIN=docker
    DOCKER_BIN=podman
elif [ -x "$( command -v podman )" ]; then
    DOCKER_BIN=podman
else
    DOCKER_BIN=docker
fi

VOLUME_FLAGS=""
if [ -x "$( command -v getenforce )" ] && [ "$( getenforce | xargs )" == "Enforcing" ]; then
    VOLUME_FLAGS=":z"
fi

DC_LOG_FLAGS=()
if [ "${DOCKER_BIN}" == "podman" ]; then
    DC_LOG_FLAGS=(--log-driver k8s-file)
fi

function dc_diagnostics()
{
    echo "===== Samba DC container diagnostics ====="
    echo "--- State"
    $DOCKER_BIN inspect -f 'Status={{.State.Status}} ExitCode={{.State.ExitCode}} StartedAt={{.State.StartedAt}}' \
        "${DC_CONTAINER_ID}" 2>&1 || true

    echo "--- Processes"
    $DOCKER_BIN exec "${DC_CONTAINER_ID}" /bin/bash -c '
        if command -v ps >/dev/null 2>&1; then
            ps -eo pid,etime,stat,args
        else
            for d in /proc/[0-9]*; do
                echo "$( basename "${d}" ) $( tr "\0" " " < "${d}/cmdline" 2>/dev/null )"
            done
        fi' 2>&1 || true

    echo "--- Last 100 log lines"
    $DOCKER_BIN logs --tail 100 "${DC_CONTAINER_ID}" 2>&1 || true
    echo "=========================================="
}

function cleanup()
{
    if [ -n "${DC_LOGS_PID}" ] && kill -0 "${DC_LOGS_PID}" >/dev/null 2>&1; then
        kill "${DC_LOGS_PID}" >/dev/null 2>&1 || true
        wait "${DC_LOGS_PID}" >/dev/null 2>&1 || true
    fi

    if [ -n "${DC_CONTAINER_ID}" ]; then
        $DOCKER_BIN rm --force "${DC_CONTAINER_ID}" >/dev/null 2>&1 || true
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
    "${DC_LOG_FLAGS[@]}" \
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

echo "Waiting for Samba to come online (timeout ${DC_STARTUP_TIMEOUT}s)"

# Stream the container output while we wait so CI shows live progress of
# the apt install, domain provisioning, and samba startup.
$DOCKER_BIN logs --follow "${DC_CONTAINER_ID}" &
DC_LOGS_PID=$!

DC_WAIT_START=${SECONDS}
while true; do
    DC_STATE=$( $DOCKER_BIN inspect -f '{{.State.Status}}' "${DC_CONTAINER_ID}" 2>/dev/null || echo "missing" )
    if [ "${DC_STATE}" != "running" ]; then
        # Let the log follower drain the remaining container output before
        # reporting the failure. It exits on its own once the container has.
        wait "${DC_LOGS_PID}" >/dev/null 2>&1 || true
        DC_LOGS_PID=""

        DC_EXIT_CODE=$( $DOCKER_BIN inspect -f '{{.State.ExitCode}}' "${DC_CONTAINER_ID}" 2>/dev/null || echo "unknown" )
        echo "Samba DC container is no longer running (state: ${DC_STATE}, exit code: ${DC_EXIT_CODE})" 1>&2
        exit 1
    fi

    if $DOCKER_BIN exec "${DC_CONTAINER_ID}" pidof samba >/dev/null 2>&1; then
        break
    fi

    if (( SECONDS - DC_WAIT_START >= DC_STARTUP_TIMEOUT )); then
        # Stop the follower first so the diagnostics do not interleave with
        # any output it is still streaming.
        kill "${DC_LOGS_PID}" >/dev/null 2>&1 || true
        wait "${DC_LOGS_PID}" >/dev/null 2>&1 || true
        DC_LOGS_PID=""

        echo "Timed out after ${DC_STARTUP_TIMEOUT}s waiting for Samba to come online" 1>&2
        dc_diagnostics 1>&2
        exit 1
    fi

    sleep 2
done

# Stop streaming the DC logs now that Samba is online.
kill "${DC_LOGS_PID}" >/dev/null 2>&1 || true
wait "${DC_LOGS_PID}" >/dev/null 2>&1 || true
DC_LOGS_PID=""
echo "Samba is online"

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

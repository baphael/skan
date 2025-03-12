#!/usr/bin/env bash

PIDS=()
SCRIPT_PATH="$(dirname $(realpath -- $0))"
TMP_PATH="${SCRIPT_PATH%/}/tmp_skan"
TMP_FILE="${TMP_PATH%/}/tmp_skan"
MAX_HOSTS=4096 #/20
# Simple IPv4 PCRE pattern
CIDR_PATTERN="(\d{1,3}\.){3}\d{1,3}/\d{1,2}"

if ! ( [[ "${TMP_PATH}" == "${SCRIPT_PATH}"* ]] || (( ${#TMP_PATH} > ${#SCRIPT_PATH} )) ); then
    echo "${TMP_PATH}" must be subpath of "${SCRIPT_PATH}" !
    exit 11
fi

if ! ( [[ "${TMP_FILE}" == "${TMP_PATH}"* ]] || (( ${#TMP_FILE} > ${#TMP_PATH} )) ); then
    echo "${TMP_FILE}" must be subpath of "${TMP_PATH}" !
    exit 12
fi

echo -n "Check privileges... "
if ! (( $(id -u) )); then
    echo KO
    echo "This script should NOT be executed as superuser."
    exit 1
fi
echo OK

echo -n "Check dependencies... "
dpkg -l prips &>/dev/null
if (( $? != 0 )); then
    echo KO
    echo "This scipt relies on prips and it seems it is not installed. To install it, run 'apt install prips' as superuser."
    exit 2
fi
echo OK

function usage() {
    SELF="$(basename ${0})"
    cat <<EOF

Description:
    Asynchronous (fast af) subnet scanner.

Usage:
    "${SELF}" [-t|--timeout SECONDS] [-o|--output FILE] [-i|--identity FILE] [-p|--port PORT] [-r|--refused] [-3|--ping|--icmp] CIDR
    Press ^C [CTRL+c] to stop

Mandatory argument:
    CIDR : must be a valid subnet (ex : 192.168.1.0/24). A host address will not work (ex : 192.168.1.1/24).

Optional arguments:
    -h, --help              Display this help message and exit.
    -t, --timeout SECONDS   SSH connection timeout. Cannot be below 1 nor above 59. Default is 1.
    -o, --output FILE       Output file.
    -i, --identity FILE     Path to private key for SSH connections.
    -p, --port              Specify SSH port. Default is 22.
    -r, --refused           Include hosts with port 22 opened but connection refused.
    -3, --ping, --icmp      Include hosts with response to ping (L3 ICMP echo response)

Examples:
    ./${SELF} 192.168.0.0/24                Scan addresses from 192.168.0.0 to 192.168.0.255. Prints results in STDOUT.
    ./${SELF} -p 2222 -3 -r 192.168.0.0/24  Same but runs much deeper scan.
    ./${SELF} -t 2 192.168.0.0/24           Same but with a ssh connection timeout of 2s. Prints results in STDOUT.
    ./${SELF} -o scan.csv 192.168.0.0/24    Same, prints results in both STDOUT and "scan.csv"

Notes :
    Standard scan retrieves hostname, IP addresses and listening ports (TCP/UDP) but requires SSH key-based access.
    Extended scanning methods (-r and -3) do not require any key or password but will not retrieve hostname or listening ports.
EOF

}

echo -n "Parse arguments... "
TIMEOUT=1
PORT=22
REFUSED=0
PING=0
OUTPUT=""
PRIVATE_KEY=""
CIDR=""
while (( $# )); do
    case $1 in
        -t|--timeout)
            if (( $(echo "${2}" | grep -Pc "^\d+$") )); then
                if (( "${2}" >= 3 )); then
                    echo "WARNING: a timeout of 3s can take time !"
                fi
                if (( "${2}" < 1 || "${2}" > 59 )); then
                    echo KO
                    echo "Assertion violated: 1 < ${2} < 59 !"
                    exit 3
                fi
                TIMEOUT="${2}"
            fi
            shift
            shift
            ;;
        -o|--output)
            if [[ -s "${2}" ]]; then
                echo "File ${2} already exists. Overwrite [1|2] ? "
                select ans in yes no; do
                    case $ans in
                        "yes")
                            > "${2}"
                            break
                            ;;
                        *)
                            exit 8
                            ;;
                    esac
                done
            fi
            OUTPUT="${2}"
            shift
            shift
            ;;
        -p|--port)
            if (( $(echo "${2}" | grep -Pc "^\d+$") )); then
                if (( "${2}" > 65535 )); then
                    echo KO
                    echo "Invalid port ${2} !"
                    exit 14
                fi
            fi
            PORT=${2}
            shift
            shift
            ;;
        -i|--identity)
            if [[ -s "${2}" ]]; then
                PRIVATE_KEY="${2}"
            else
                echo KO
                echo "${2} not found or empty"
                exit 9
            fi
            shift
            shift
            ;;
        -r|--refused)
            REFUSED=1
            shift
            ;;
        -3|--ping|--icmp)
            PING=1
            shift
            ;;
        -h|--help)
            usage
            exit 5
            ;;
        *)
            if (( ! $(echo "${1}" | grep -coP ${CIDR_PATTERN}) )) || [[ ! -z ${CIDR} ]]; then
                echo KO
                echo "This script requires one argument of the form X.X.X.X/X"
                usage
                exit 6
            fi
            CIDR="${1}"
            shift
            ;;
    esac
done
if [[ -z "${CIDR}" ]]; then
    echo KO
    echo "This script requires one argument of the form X.X.X.X/X"
    usage
    exit 7
fi
echo OK

if [[ ! -d "${TMP_PATH}" ]]; then
    mkdir -p "${TMP_PATH}"
    if [[ ! -d "${TMP_PATH}" ]]; then
        echo KO
        echo "Could not create temporary directory ${TMP_PATH}"
        exit 10
    fi
fi

RANGE=$(prips ${CIDR})
N_HOSTS=$(echo ${RANGE}|wc -w)
if (( ${N_HOSTS} > ${MAX_HOSTS} )); then
    echo "Number of hosts (${N_HOSTS}) should not exceed ${MAX_HOSTS}"
    exit 13
fi

START_TIME=$(date +%s)

echo "[Running standard SSH scan]"
COUNT=1
for i in $(prips ${CIDR}); do
    COUNT=$(( COUNT+1 ))
    ssh -p ${PORT} ${PRIVATE_KEY:+-i} ${PRIVATE_KEY:-} -o connectTimeout=${TIMEOUT} -o strictHostKeyChecking=no -o passwordAuthentication=no ${i} "
        echo -n \$(hostname) && \
        echo -n ',' && \
        echo -n \$(hostname -I) && \
        echo -n ',' && \
        ss -tulpn '! src 127.0.0.0/8 and ! src [::1]' | \
            tail +2 | \
            tr -s ' ' | \
            cut -d' ' -f 5 | \
            rev | \
            cut -d: -f1 | \
            rev | \
            sort -u | \
            tr '\n' ' ' && \
        echo
    " 2>/dev/null > "${TMP_PATH%/}/${COUNT}-${i}" & #ASYNC
    PIDS+=($!)
done

# AWAIT
for pid in "${PIDS[@]}"; do
    wait ${pid}
done

cat "${TMP_PATH}/"*

if (( ${REFUSED} )); then
    COUNT=1
    PIDS=()
    echo
    echo "[Running extended SSH scan]"
    for i in $(prips ${CIDR}); do
        COUNT=$(( COUNT+1 ))
        if [[ ! -f "${TMP_PATH%/}/${COUNT}-${i}" || ! -s "${TMP_PATH%/}/${COUNT}-${i}" ]]; then
            (
                nc -zvvw ${TIMEOUT} ${i} ${PORT} &> "${TMP_PATH%/}/${COUNT}-${i}"
                if (( $(grep -ciP "connection refused" "${TMP_PATH%/}/${COUNT}-${i}") )); then
                    echo "UNKNOWN,${i},${PORT}" | tee "${TMP_PATH%/}/${COUNT}-${i}"
                else
                    >"${TMP_PATH%/}/${COUNT}-${i}"
                fi
            ) & #ASYNC
            PIDS+=($!)
        fi
    done
fi

# AWAIT
for pid in "${PIDS[@]}"; do
    wait ${pid}
done

if (( ${PING} )); then
    COUNT=1
    PIDS=()
    echo
    echo "[Running extended ICMP scan]"
    for i in $(prips ${CIDR}); do
        COUNT=$(( COUNT+1 ))
        if [[ ! -f "${TMP_PATH%/}/${COUNT}-${i}" || ! -s "${TMP_PATH%/}/${COUNT}-${i}" ]]; then
            (
                ping -c1 -W${TIMEOUT} ${i} &>/dev/null
                if (( $? == 0 )); then
                    echo "PING,${i}" | tee "${TMP_PATH%/}/${COUNT}-${i}"
                fi
            ) & #ASYNC
            PIDS+=($!)
        fi
    done
fi

# AWAIT
for pid in "${PIDS[@]}"; do
    wait ${pid}
done

# CONCAT ALL RESULTS
cat <(echo hostname,@IP,listening ports) "${TMP_PATH%/}/"* > "${TMP_FILE}"

if [[ ! -z "${OUTPUT}" ]]; then
    mv "${TMP_FILE}" "${OUTPUT}"
fi

# FLUSH TMP DIRECTORY
rm -r "${TMP_PATH}"

echo "[DURATION] $(( $(date +%s) - ${START_TIME} )) seconds"

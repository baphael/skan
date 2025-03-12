#!/usr/bin/env bash

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

# FLUSH TMP DIRECTORY ON INTERRUPTION
trap ctrl_c INT
function ctrl_c() {
    rm -r "${TMP_PATH}" 2>/dev/null
    exit 255
}

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
    "${SELF}" [-p|--port PORT] [-u|--user USERNAME] [-t|--timeout SECONDS] [-e|--extended PORTS] [-3|--ping|--icmp] [-r|--refused] [-o|--output FILE] [-i|--identity FILE] [-h|--help] CIDR
    Press ^C [CTRL+c] to stop

Mandatory argument:
    CIDR : must be a valid subnet (ex : 192.168.1.0/24). A host address will not work (ex : 192.168.1.1/24).

Optional arguments:
    -p, --port PORT         Specify SSH port. Default is 22.
    -u, --user USERNAME     SPECIFY SSH username. Default is your current username.
    -t, --timeout SECONDS   SSH connection timeout. Cannot be below 1 nor above 59. Default is 1.
    -e, --extended PORT     Extended ports scan. Defaults to SSH port.
                            Can be used multiple times for multiple ports ranges or lists.
                            Supports ranges START-END.
                            Supports ,-delimited list of ports PORTA,PORTB,PORTC...
    -3, --ping, --icmp      Extended ICMP scan. Includes hosts with L3 ICMP echo response (ping).
    -r, --refused           Include "connection refused" status in extended ports scan.
                            Default kept statuses are "succeeded", "version mismatch" and "permission denied".
    -o, --output FILE       Output file.
    -i, --identity FILE     Path to private key for SSH connections.
    -h, --help              Display this help message and exit.

Examples:
    ./${SELF} -u jdoe 192.168.0.0/24        Scan addresses from 192.168.0.0 to 192.168.0.255 using the standard SSH key-based method with remote user "jdoe".
    ./${SELF} -3 -e 22-25 -e 80,443 192.168.0.0/24  Runs a much deeper scan with ports 22, 23, 24, 25, 80, 443 and ICMP (ping).
    ./${SELF} -t 2 192.168.0.0/24           Basic SSH key-based scan with a ssh connection timeout of 2s.
    ./${SELF} -o scan.csv 192.168.0.0/24    Same, prints results in both STDOUT and "scan.csv".

Notes :
    Standard scan retrieves hostname, IP addresses and listening ports (TCP/UDP) but requires SSH key-based access.
    Extended ports scan (-e) do not require any key but will not retrieve hostname.
    Extended ICMP (-3) do not require any key but will not retrieve hostname or ports.
EOF

}

echo -n "Parse arguments... "
TIMEOUT=1
SSH_PORT=22
PORTS=()
USER=$(id -un)
EXTENDED=""
PING=""
OUTPUT=""
PRIVATE_KEY=""
NC_STATUSES="succeeded|version mismatch|permission denied"
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
        -u|--user)
            if [[ ! "${2}" =~ ^[a-z][-a-z0-9_]*\$?$ ]]; then
                echo KO
                echo "Invalid username ${2}"
                exit 16
            fi
            USER="${2}"
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
            SSH_PORT=${2}
            shift
            shift
            ;;
        -e|--extended)
            EXTENDED=1
            if (( $(echo "${2}" | grep -Pc "^\d+$") )); then
                    if (( ${2} > 0 && ${2} < 65536 )); then
                        PORTS+=(${2})
                    else
                        echo "Illegal port ${2} will be ignored."
                    fi
            elif (( $(echo "${2}" | grep -Pc "^\d+-\d+$") )); then
                port_range_lower_bound=$(echo "${2}"|cut -d- -f1)
                port_range_upper_bound=$(echo "${2}"|cut -d- -f2)
                if (( ! (${port_range_lower_bound} < ${port_range_upper_bound}) )); then
                    echo "Illegal port range. Assertion violated: ${port_range_lower_bound} < ${port_range_upper_bound} ! This port range will be ignored."
                fi
                PORTS+=($(seq ${port_range_lower_bound} ${port_range_upper_bound}))
            elif (( $(echo "${2}" | grep -Pc "^(\d+,)+\d+$") )); then
                ports_list=($(echo "${2}" | tr -s "," " "))
                for port in ${ports_list[@]}; do
                    if (( ${port} > 0 && ${port} < 65536 )); then
                        PORTS+=(${port})
                    else
                        echo "Illegal port ${port} will be ignored."
                    fi
                done
            fi
            shift
            shift
            ;;
        -i|--identity)
            if [[ -s $(realpath "${2}") ]]; then
                PRIVATE_KEY=$(realpath "${2}")
            else
                echo KO
                echo "${2} not found or empty"
                exit 9
            fi
            shift
            shift
            ;;
        -3|--ping|--icmp)
            PING=1
            shift
            ;;
        -r|--refused)
            NC_STATUSES+="|connection refused"
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

# EXTENDED PORTS SCAN DEFAULTS TO SSH PORTS
PORTS=(${PORTS[@]:-${SSH_PORT}})

echo OK
echo

if [[ ! -d "${TMP_PATH}" ]]; then
    mkdir -p "${TMP_PATH}" 2>/dev/null
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
# COUNT IS USED AS FILE PREFIX FOR ORDERING RESULTS
COUNT=0
PIDS=()
for i in $(prips ${CIDR}); do
    COUNT=$(( COUNT+1 ))
    ssh -p ${PORT:-22} ${PRIVATE_KEY:+-i} ${PRIVATE_KEY:-} -o ConnectTimeout=${TIMEOUT} -o StrictHostKeyChecking=no -o PasswordAuthentication=no -o KbdInteractiveAuthentication=no -o BatchMode=yes "${USER}@${i}" "
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

# SORT ASCENNDING
FILES=($(find "${TMP_PATH%/}" -maxdepth 1 -type f ! -empty 2>/dev/null | sort -V))
cat "${FILES[@]}" 2>/dev/null

if (( ${EXTENDED} )); then
    COUNT=0
    echo
    echo "[Running extended ports scan]"
    PIDS=()
    for i in $(prips ${CIDR}); do
        COUNT=$(( COUNT+1 ))
        (
            # ONLY IF PREVIOUS SCAN RETRIEVED NOTHING
            if [[ ! -f "${TMP_PATH%/}/${COUNT}-${i}" || ! -s "${TMP_PATH%/}/${COUNT}-${i}" ]]; then
                SUBPIDS=()
                for p in ${PORTS[@]}; do
                    (
                        NC=$(nc -nzvvw ${TIMEOUT} ${i} ${p} 2>&1)

                        # MUST USE TMP FILE BECAUSE VARIABLES DEFINED INSIDE SUBSHELL ARE NOT ACCESSIBLE OUTSIDE
                        if (( $(echo "${NC}" | grep -ciP "${NC_STATUSES}") )); then
                            if [[ ! -f "${TMP_PATH%/}/${COUNT}-${i}-ports" || ! -s "${TMP_PATH%/}/${COUNT}-${i}-ports" ]]; then
                                echo -n "${p}" >> "${TMP_PATH%/}/${COUNT}-${i}-ports"
                            else
                                echo -n " ${p}" >> "${TMP_PATH%/}/${COUNT}-${i}-ports"
                            fi
                        fi
                    ) & # ASYNC
                    SUBPIDS+=($!)
                done
                # AWAIT
                for pid in "${SUBPIDS[@]}"; do
                    wait ${pid}
                done

                # CONSOLIDATE FINAL FILE AND REMOVE TMP PORTS FILE
                if [[ -s "${TMP_PATH%/}/${COUNT}-${i}-ports" ]] && ! (( $(grep -c "," "${TMP_PATH%/}/${COUNT}-${i}-ports") )); then
                    cat <(echo "UNKNOWN,${i},") "${TMP_PATH%/}/${COUNT}-${i}-ports" 2>/dev/null | tr -d "\n" > "${TMP_PATH%/}/${COUNT}-${i}-EXT"
                    echo >>"${TMP_PATH%/}/${COUNT}-${i}-EXT"
                    rm "${TMP_PATH%/}/${COUNT}-${i}-ports" 2>/dev/null
                fi
            fi
        ) & # ASYNC
        PIDS+=($!)
    done
    # AWAIT
    for pid in "${PIDS[@]}"; do
        wait ${pid}
    done

    # PRINT TO STDOUT (ASCENDING ORDER)
    FILES=($(find "${TMP_PATH%/}" -maxdepth 1 -type f ! -empty -name "*-EXT" 2>/dev/null | sort -V))
    for ext in "${FILES[@]}"; do
        if [[ -s "${ext}" ]]; then
            cat "${ext}" 2>/dev/null
            # MERGE EXTENDED SCAN FILE INTO ORIGINAL SSH SCAN FILE
            mv "${ext}" "${ext%-EXT}" 2>/dev/null
        fi
    done
fi

if (( ${PING} )); then
    COUNT=0
    PIDS=()
    echo
    echo "[Running extended ICMP scan]"
    for i in $(prips ${CIDR}); do
        COUNT=$(( COUNT+1 ))
        # ONLY IF PREVIOUS SCANS RETRIEVED NOTHING
        if [[ ! -f "${TMP_PATH%/}/${COUNT}-${i}" || ! -s "${TMP_PATH%/}/${COUNT}-${i}" ]]; then
            (
                ping -c1 -W${TIMEOUT} ${i} &>/dev/null
                if (( $? == 0 )); then
                    echo "UNKNOWN,${i}" > "${TMP_PATH%/}/${COUNT}-${i}-ICMP"
                fi
            ) & #ASYNC
            PIDS+=($!)
        fi
    done

    # AWAIT
    for pid in "${PIDS[@]}"; do
        wait ${pid}
    done

    # PRINT TO STDOUT (ASCENDING ORDER)
    FILES=($(find "${TMP_PATH%/}" -maxdepth 1 -type f ! -empty -name "*-ICMP" 2>/dev/null | sort -V))
    for icmp in "${FILES[@]}"; do
        if [[ -s "${icmp}" ]]; then
            cat "${icmp}" 2>/dev/null
            # MERGE ICMP SCAN FILE INTO ORIGINAL SSH SCAN FILE
            mv "${icmp}" "${icmp%-EXT}" 2>/dev/null
        fi
    done
fi

# CONCAT ALL RESULTS IN ASCENDING VERSION ORDER
FILES=($(find "${TMP_PATH%/}" -maxdepth 1 -type f ! -empty 2>/dev/null | sort -V))
cat <(echo hostname,@IP,listening ports) "${FILES[@]}" > "${TMP_FILE}" 2>/dev/null
echo

FOUND=$(wc -l "${TMP_FILE}" 2>/dev/null | cut -d' ' -f1)
if (( $(echo "${FOUND}" | grep -Pc "^\d+$") )) && (( ${FOUND} > 0 )); then
    FOUND=$(( FOUND-1 ))
    echo  "${FOUND} host(s) found."
    echo
fi

if [[ ! -z "${OUTPUT}" ]]; then
    mv "${TMP_FILE}" "${OUTPUT}" 2>/dev/null
fi

# FLUSH TMP DIRECTORY
rm -r "${TMP_PATH}" 2>/dev/null

echo "[DURATION] $(( $(date +%s) - ${START_TIME} )) seconds"

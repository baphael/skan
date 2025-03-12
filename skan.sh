#!/usr/bin/env bash

SCRIPT_PATH="$(dirname $(realpath -- $0))"
TMP_PATH="${SCRIPT_PATH%/}/tmp_skan"
TMP_FILE="${TMP_PATH%/}/tmp_skan"
MAX_HOSTS=4096 #/20

# Limit of parallel threads
MAX_THREADS=$(cat /proc/sys/kernel/threads-max 2>/dev/null)
CURRENT_N_THREADS=$(ps -eLf | wc -l)
if (( $(echo "${MAX_THREADS}${CURRENT_N_THREADS}" | grep -Pc "^\d+$") && $MAX_THREADS && $CURRENT_N_THREADS )); then
    MAX_THREADS=$(( ${MAX_THREADS} / $CURRENT_N_THREADS )) # Limit = threads-max / current number of threads
fi
# Fallback to default value
if ! (( $MAX_THREADS )); then MAX_THREADS=16; fi

# Limit of parallel "sub-threads" per thread
MAX_SUBTHREADS=$( echo ${MAX_THREADS} | awk '{print(int(sqrt($0)))}' ) # square root of MAX_THREADS
# Fallback to default value
if ! (( $MAX_SUBTHREADS )); then MAX_SUBTHREADS=4; fi

# Simple IPv4 PCRE pattern
IP_PATTERN="(\d{1,3}\.){3}\d{1,3}"
# Simple IPv4 PCRE pattern
CIDR_PATTERN="${IP_PATTERN}/\d{1,2}"

if ! ( [[ "${TMP_PATH}" == "${SCRIPT_PATH}"* ]] || (( ${#TMP_PATH} > ${#SCRIPT_PATH} )) ); then
    echo "${TMP_PATH}" must be subpath of "${SCRIPT_PATH}" !
    exit 11
fi

if ! ( [[ "${TMP_FILE}" == "${TMP_PATH}"* ]] || (( ${#TMP_FILE} > ${#TMP_PATH} )) ); then
    echo "${TMP_FILE}" must be subpath of "${TMP_PATH}" !
    exit 12
fi

if [[ ! -d "${TMP_PATH}" ]]; then
    mkdir -p "${TMP_PATH}" 2>/dev/null
    if [[ ! -d "${TMP_PATH}" ]]; then
        echo KO
        echo "Could not create temporary directory ${TMP_PATH}"
        exit 10
    fi
fi

# Turn CIDR into list of IPs
function cidr2ips() {
    if (( $# != 1 )); then
        echo "CIDR to IPs conversion takes (only) one argument"
        exit 20
    fi
    if ! (( $(echo "${1}" | grep -cP ${CIDR_PATTERN}) )); then
        echo "Invalid CIDR ${1}"
        exit 20
    fi
    cidr="${1}"

    originalIFS=$IFS

    # Split CIDR into base IP and mask
    IFS=/ read -r base_ip mask <<< "$cidr"

    # Convert base IP to a 32-bit integer
    IFS=. read -r i1 i2 i3 i4 <<< "$base_ip"
    ip=$(( (i1 << 24) + (i2 << 16) + (i3 << 8) + i4 ))

    IFS=$originalIFS

    # Calculate the network mask dynamically based on CIDR
    netmask=$(( (1 << (32 - mask)) - 1 ))
    netmask=$(( ~netmask & 0xFFFFFFFF ))

    # Calculate start and end of the range
    start=$((ip & netmask))
    end=$((start | ~netmask & 0xFFFFFFFF))

    # Generate all IPs in the range
    for ((i = start; i <= end; i++)); do
        printf "%d.%d.%d.%d\n" $(( (i >> 24) & 0xFF )) $(( (i >> 16) & 0xFF )) $(( (i >> 8) & 0xFF )) $((i & 0xFF))
    done
}

# Flush tmp directory on interruption
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

function usage() {
    SELF="$(basename ${0})"
    cat <<EOF

Description:
    Asynchronous subnet scanner.

Usage:
    "${SELF}" [-p|--port PORT] [-u|--user USERNAME] [-t|--timeout SECONDS] [-e|--extended PORTS] [-3|--ping|--icmp] [-r|--refused] [-o|--output FILE] [-i|--identity FILE] [-h|--help] CIDR
    Press ^C [CTRL+c] to stop

Mandatory argument:
    CIDR : must be a valid subnet (ex : 192.168.1.0/24). A host address will not work (ex : 192.168.1.1/24).

Optional arguments:
    Global options
    -t, --timeout SECONDS   SSH connection timeout. Cannot be below 1 nor above 59. Default is 1.

    SSH-specific options
    -p, --port PORT         Specify SSH port. Default is 22.
    -u, --user USERNAME     Specify SSH username. Default is your current username.
    -i, --identity FILE     Path to private key for SSH connections.

    Extended scanning methods
    -e, --extended PORT     Extended ports scan. Defaults to SSH port.
                            Can be used multiple times for multiple ports ranges or lists.
                            Supports ranges START-END.
                            Supports ,-delimited list of ports PORTA,PORTB,PORTC...
    -r, --refused           Include "connection refused" status in extended ports scan.
                            Default kept statuses are "succeeded", "open", "connected", "version mismatch" and "permission denied".
                            Discouraged if scanning a subnet matching your current broadcast domain !
    -3, --ping, --icmp      Extended ICMP scan. Includes hosts with L3 ICMP echo response (ping).

    Miscellaneous
    -o, --output FILE       Output file.

    -f, --fast              Increase parallel threads limit. Warning, it may cause CPU overload !
    -s, --slow              Decrease parallel threads limit. Scans will be slower, but CPU load should stay quite low.

    -v, --verbose           Verbose mode.
    -vv, --super-verbose    Verbose mode with parallel threads guardrail awaits.
    -vvv, --turbo-verbose   Verbose mode with parallel threads and subthreads guardrail awaits. Output will be messy !

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
VERBOSE=""
SUPER_VERBOSE=""
TURBO_VERBOSE=""
PRIVATE_KEY=""
SLOW=""
FAST=""
REFUSED=""
NC_STATUSES="open|succeeded|connected to|version mismatch|permission denied"
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
            REFUSED=1
            shift
            ;;
        -f|--fast)
            if (( ${SLOW} )); then
                echo KO
                echo "Scan cannot be fast and slow !"
                exit 18
            fi

            FAST=1

            MAX_THREADS=$(( ${MAX_THREADS} * 3 / 2 ))
            # Fallback to default value
            if ! (( $MAX_THREADS )); then MAX_THREADS=16; fi

            # Limit of parallel "sub-threads" per thread
            MAX_SUBTHREADS=$( echo ${MAX_THREADS} | awk '{print(int(sqrt($0)))}' ) # square root of MAX_THREADS
            # Fallback to default value
            if ! (( $MAX_SUBTHREADS )); then MAX_SUBTHREADS=4; fi

            shift
            ;;
        -s|--slow)
            if (( ${FAST} )); then
                echo KO
                echo "Scan cannot be fast and slow !"
                exit 18
            fi

            SLOW=1

            MAX_THREADS=$(( ${MAX_THREADS} * 2 / 3 ))
            # Fallback to default value
            if ! (( $MAX_THREADS )); then MAX_THREADS=16; fi

            # Limit of parallel "sub-threads" per thread
            MAX_SUBTHREADS=$( echo ${MAX_THREADS} | awk '{print(int(sqrt($0)))}' ) # square root of MAX_THREADS
            # Fallback to default value
            if ! (( $MAX_SUBTHREADS )); then MAX_SUBTHREADS=4; fi

            shift
            ;;
        -v|--verbose)
            VERBOSE=1
            shift
            ;;
        -vv|--super-verbose)
            VERBOSE=1
            SUPER_VERBOSE=1
            shift
            ;;
        -vvv|--turbo-verbose)
            VERBOSE=1
            SUPER_VERBOSE=1
            TURBO_VERBOSE=1
            shift
            ;;
        -h|--help)
            usage
            exit 5
            ;;
        *)
            if (( ! $(echo "${1}" | grep -cP ${CIDR_PATTERN}) )) || [[ ! -z ${CIDR} ]]; then
                echo KO
                echo "This script takes only one positional argument of the form X.X.X.X/X"
                usage
                exit 6
            fi
            CIDR="${1}"
            RANGE=($(cidr2ips "${CIDR}"))
            N_HOSTS=${#RANGE[@]}
            if (( ${N_HOSTS} > ${MAX_HOSTS} )); then
                echo KO
                echo "Number of hosts (${N_HOSTS}) should not exceed ${MAX_HOSTS}"
                exit 13
            fi
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

if (( ${VERBOSE} )); then
    echo "CIDR : ${CIDR} (${N_HOSTS} host(s))"
    echo -e "Scanning methods :\n\t- standard key-based SSH on port ${SSH_PORT} with user ${USER}"
    if (( ${EXTENDED} )); then
        echo -ne "\t- extended scan on ports ${PORTS[@]}"
        if (( ${REFUSED} )); then
            echo " (with refused connections)"
        else
            echo
        fi
    fi
    if (( ${PING} )); then echo -e "\t- extended ICMP scan"; fi
    echo "Timeout : ${TIMEOUT} second(s)"
    if [[ ! -z "${PRIVATE_KEY}" ]]; then echo "Custom private key : ${PRIVATE_KEY}"; fi
    if [[ ! -z "${OUTPUT}" ]]; then echo "Output file : ${OUTPUT}"; fi
    echo "Temporary path : ${TMP_PATH}"
    echo "Temporary file : ${TMP_FILE}"
    echo "Maximum parallel thread(s) : ${MAX_THREADS}"
    echo "Maximum parallel \"sub-thread(s)\" per thread : ${MAX_SUBTHREADS}"
    echo
fi

ETA_SSH=0
ETA_EXT=0
ETA_ICMP=0
ETA_SSH=$(( 2 *  ${N_HOSTS} * ${TIMEOUT} / ${MAX_THREADS} ))
if (( ${VERBOSE} )); then echo "Key-base SSH scan ETA : ${ETA_SSH} second(s)"; fi

if (( ${EXTENDED} )); then
    ETA_EXT=$(( 2 * ${N_HOSTS} * ${#PORTS[@]} * ${TIMEOUT} / ${MAX_THREADS} / ${MAX_SUBTHREADS} ))
    if (( ${VERBOSE} )); then echo "Extended ports scan ETA : ${ETA_EXT} second(s)"; fi
fi

if (( ${ICMP} )); then
    ETA_ICMP=$(( 2 * ${N_HOSTS} * ${TIMEOUT} / ${MAX_THREADS} ))
    if (( ${VERBOSE} )); then echo "ICMP scan ETA : ${ETA_ICMP} second(s)"; fi
fi

ETA=$(( ${ETA_SSH} + ${ETA_EXT} + ${ETA_ICMP} ))

echo "ETA : ${ETA} second(s)"
echo

if (( ${MAX_THREADS} < 16 || ${MAX_SUBTHREADS} < 4 )); then
    echo "[WARNING] MAX_THREADS=${MAX_THREADS} MAX_SUBTHREADS=${MAX_SUBTHREADS} might be slow !"
    echo
fi

START_TIME=$(date +%s)

echo "[Running standard SSH scan]"
# COUNT IS USED AS FILE PREFIX FOR ORDERING RESULTS
COUNT=0
PIDS=()
for i in "${RANGE[@]}"; do
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

    if (( ${#PIDS[@]} >= ${MAX_THREADS} )); then
        # GUARDRAIL AWAIT
        if (( ${SUPER_VERBOSE} )); then echo -n "Guardrail await (${MAX_THREADS} parallel threads)... "; fi
        for pid in "${PIDS[@]}"; do
            wait ${pid}
        done
        PIDS=()
        if (( ${SUPER_VERBOSE} )); then echo "OK"; fi
    fi
done
# AWAIT
for pid in "${PIDS[@]}"; do
    wait ${pid}
done

# SORT ASCENNDING
FILES=($(find "${TMP_PATH%/}" -maxdepth 1 -type f ! -empty 2>/dev/null | sort -V))
if (( ${#FILES[@]} )); then cat "${FILES[@]}" 2>/dev/null; fi

if (( ${EXTENDED} )); then
    COUNT=0
    echo
    echo "[Running extended ports scan]"
    PIDS=()
    for i in "${RANGE[@]}"; do
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

                    if (( ${#SUBPIDS[@]} >= ${MAX_SUBTHREADS} )); then
                        # GUARDRAIL AWAIT
                        if (( ${TURBO_VERBOSE} )); then echo "Guardrail await (${MAX_SUBTHREADS} parallel \"subthreads\")"; fi
                        for pid in "${SUBPIDS[@]}"; do
                            wait ${pid}
                        done
                        SUBPIDS=()
                    fi
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

        if (( ${#PIDS[@]} >= ${MAX_THREADS} )); then
            # GUARDRAIL AWAIT
            if (( ${SUPER_VERBOSE} )); then echo -n "Guardrail await (${MAX_THREADS} parallel threads)... "; fi
            for pid in "${PIDS[@]}"; do
                wait ${pid}
            done
            PIDS=()
            if (( ${SUPER_VERBOSE} )); then echo "OK"; fi
        fi
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
    for i in "${RANGE[@]}"; do
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

            if (( ${#PIDS[@]} >= ${MAX_THREADS} )); then
                # GUARDRAIL AWAIT
                if (( ${SUPER_VERBOSE} )); then echo -n "Guardrail await (${MAX_THREADS} parallel threads)... "; fi
                for pid in "${PIDS[@]}"; do
                    wait ${pid}
                done
                PIDS=()
                if (( ${SUPER_VERBOSE} )); then echo "OK"; fi
            fi
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
            mv "${icmp}" "${icmp%-ICMP}" 2>/dev/null
        fi
    done
fi

# CONCAT ALL RESULTS IN ASCENDING VERSION ORDER
FILES=($(find "${TMP_PATH%/}" -maxdepth 1 -type f ! -empty 2>/dev/null | sort -V))
if (( ${#FILES[@]} )); then
    cat <(echo hostname,@IP,listening ports) "${FILES[@]}" > "${TMP_FILE}" 2>/dev/null
fi
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

#!/usr/bin/env bash

# Echo on stderr
function echo_error() {
    echo "$*" >&2
}

# Check privileges
if ! (( $(id -u) )); then
    echo_error "This script should NOT be executed as superuser."
    exit 1
fi

# Turn CIDR into list of IPs
function cidr2ips() {
    if (( $# != 1 )); then
        echo_error "CIDR to IPs conversion takes (only) one argument"
        exit 20
    fi
    if ! (( $(echo "${1}" | grep -cP ${CIDR_PATTERN}) )); then
        echo_error "Invalid CIDR ${1}"
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

function usage() {
    SELF="$(basename "${0}")"
    cat <<EOF

Description:
    Asynchronous subnet scanner.

Usage:
    "${SELF}" [-k|--key-based-ssh] [-e|--extended PORTS] [-3|--ping|--icmp] [-t|--timeout SECONDS] [-f|--fast] [-s|--slow] [-p|--port PORT] [-u|--user USERNAME] [-i|--identity FILE] [-r|--refused] [-c|--csv FILE] [-a|--ansible FILE] [-q|--quiet] [-v|--verbose] [-vv|--super-verbose] [-h|--help] CIDR
    Press ^C [CTRL+c] to stop

Mandatory argument:
    CIDR : A network subnet in CIDR notation (ex : 192.168.1.0/24).

    Scanning method. At least one of :
    -k, --key-based-ssh     Key-based SSH method.
    -e, --extended PORTS    Extended ports scan.
                            Can be used multiple times for multiple ports ranges or lists.
                            Supports ranges START-END.
                            Supports ,-delimited list of ports PORTA,PORTB,PORTC...
    -3, --ping, --icmp      ICMP scan. Includes hosts with L3 ICMP echo response (ping).

    Scanning methods have the following precedence level : ssh > extended > ping.
    This means if a host is found during SSH scan, it won't appear again in extended or ICMP scan.

Optional arguments:
    Global options
    -t, --timeout SECONDS   Connection timeout. Cannot be below 1 nor above 59. Default is 1.
    -f, --fast              Increase parallel threads limit. Warning, it may cause CPU overload !
    -s, --slow              Decrease parallel threads limit. Scans will be slower, but CPU load should stay quite low.

    Key-based SSH options
    -p, --port PORT         Specify SSH port. Default is 22.
    -u, --user USERNAME     Specify SSH username. Default is your current username.
    -i, --identity FILE     Path to private key for SSH connections.

    Extended options
    -r, --refused           Include "connection refused" status in extended ports scan.
                            Default kept statuses are "succeeded", "open", "connected", "version mismatch" and "permission denied".
                            Discouraged if scanning a subnet matching your current broadcast domain.

    Output
    -c, --csv FILE          Output CSV-formatted file. Format "\$hostname,\$ips,\$listening_ports"
    -a, --ansible FILE      Output INI-formatted Ansible inventory file. Format "#-\$hostname ansible_host=\$ip"
    -q, --quiet             Quiet mode. Assumes "yes" to all. Errors and warnings are still printed in stderr.
                            Use stderr redirection to silent errors and warnings (2>/dev/null).
                            Requires an output file.
    -v, --verbose           Verbose mode.
    -vv, --super-verbose    Verbose mode with parallel threads guardrail awaits.

    -h, --help              Display this help message and exit.

Examples:
    ./${SELF} -k -u jdoe -p 2222 -i ~/.ssh/jdoe 192.168.0.0/24
        Key-based SSH scan on port 2222 with remote user "jdoe" and a custom private key file.
    ./${SELF} -s -k -3 -e 21-25 -e 67-69 -e 53,80,110,123,143,161,162,389,443,445,587,636,993,3306,3389,5432,5601,8000,8080,8443,8888,9200 192.168.0.0/24
        Slow SSH scan, extended scan on top #30 most used ports and ICMP scan.
    ./${SELF} -f -a ansible_inventory.ini -k -e 22,2222 -q 192.168.0.0/24
        Fast key-based SSH scan and ports scan on ports 22 and 2222 with an INI-formatted ansible inventory output file and no output on stdout.

Notes :
    Key-based SSH scan (-k) retrieves hostname, IP addresses and listening ports (TCP/UDP) but requires a valid key-based access.
    Extended ports scan (-e) do not require any key but will not retrieve hostname.
    ICMP scan (-3) do not require any key but will not retrieve hostname or ports.
EOF

}

# Global variables
SCRIPT_PATH="$(dirname "$(realpath -- "${0}")")"
TMP_PATH="${SCRIPT_PATH%/}/tmp_skan"
TMP_FILE="${TMP_PATH%/}/tmp_skan"
MAX_HOSTS=4096 #/20

# Limit of parallel threads
MAX_THREADS=$(cat /proc/sys/kernel/threads-max 2>/dev/null)
CURRENT_N_THREADS=$(ps -eLf | wc -l)
if (( $(echo "${MAX_THREADS}${CURRENT_N_THREADS}" | grep -Pc "^\d+$") && MAX_THREADS && CURRENT_N_THREADS )); then
    MAX_THREADS=$(( MAX_THREADS / CURRENT_N_THREADS )) # Limit = threads-max / current number of threads
fi
# Fallback to default value
if ! (( MAX_THREADS )); then MAX_THREADS=16; fi

# Limit of parallel "sub-threads" per thread
MAX_SUBTHREADS=$( echo "${MAX_THREADS}" | awk '{print(int(sqrt($0)))}' ) # square root of MAX_THREADS
# Fallback to default value
if ! (( MAX_SUBTHREADS )); then MAX_SUBTHREADS=4; fi

# Simple IPv4 PCRE pattern
IP_PATTERN="(\d{1,3}\.){3}\d{1,3}"
# Simple IPv4 PCRE pattern
CIDR_PATTERN="${IP_PATTERN}/\d{1,2}"

if ! ( [[ "${TMP_PATH}" == "${SCRIPT_PATH}"* ]] || (( ${#TMP_PATH} > ${#SCRIPT_PATH} )) ); then
    echo_error "${TMP_PATH}" must be subpath of "${SCRIPT_PATH}" !
    exit 11
fi

if ! ( [[ "${TMP_FILE}" == "${TMP_PATH}"* ]] || (( ${#TMP_FILE} > ${#TMP_PATH} )) ); then
    echo_error "${TMP_FILE}" must be subpath of "${TMP_PATH}" !
    exit 12
fi

if [[ ! -d "${TMP_PATH}" ]]; then
    mkdir -p "${TMP_PATH}" 2>/dev/null
    if [[ ! -d "${TMP_PATH}" ]]; then
        echo_error "Could not create temporary directory ${TMP_PATH}"
        exit 10
    fi
fi

# Parse arguments
TIMEOUT=1
SSH_PORT=22
SSH=""
PORTS=()
USER=$(id -un)
EXTENDED=""
PING=""
OUTPUT_CSV=""
OUTPUT_INI=""
OUTPUT=()
QUIET=""
VERBOSE=""
SUPER_VERBOSE=""
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
                    echo_error "WARNING: a timeout of 3s can take time !"
                fi
                if (( "${2}" < 1 || "${2}" > 59 )); then
                    echo_error "Assertion violated: 1 < ${2} < 59 !"
                    exit 3
                fi
                TIMEOUT="${2}"
            fi
            shift
            shift
            ;;
        -u|--user)
            if [[ ! "${2}" =~ ^[a-z][-a-z0-9_]*\$?$ ]]; then
                echo_error "Invalid username ${2}"
                exit 16
            fi
            USER="${2}"
            shift
            shift
            ;;
        -c|--csv)
            OUTPUT_CSV="${2}"
            OUTPUT+=( "${2}" )
            shift
            shift
            ;;
        -a|--ansible)
            OUTPUT_INI="${2}"
            OUTPUT+=( "${2}" )
            shift
            shift
            ;;
        -p|--port)
            if (( $(echo "${2}" | grep -Pc "^\d+$") )); then
                if (( "${2}" > 65535 )); then
                    echo_error "Invalid port ${2} !"
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
                    PORTS+=("${2}")
                else
                    echo_error "Illegal port ${2} will be ignored."
                fi
            elif (( $(echo "${2}" | grep -Pc "^\d+-\d+$") )); then
                port_range_lower_bound=$(echo "${2}"|cut -d- -f1)
                port_range_upper_bound=$(echo "${2}"|cut -d- -f2)
                if (( ! (port_range_lower_bound < port_range_upper_bound) )); then
                    echo_error "Illegal port range. Assertion violated: ${port_range_lower_bound} < ${port_range_upper_bound} ! This port range will be ignored."
                    IGNORED=1
                fi
                if (( port_range_lower_bound < 1 || port_range_upper_bound > 65536 )); then
                    echo_error "Illegal port range ${port_range_lower_bound}-${port_range_upper_bound} will be ignored."
                    IGNORED=1
                fi
                if ! (( IGNORED )); then mapfile -t -O "${#PORTS[@]}" PORTS < <(seq "${port_range_lower_bound}" "${port_range_upper_bound}"); fi
                IGNORED=0
            elif (( $(echo "${2}" | grep -Pc "^(\d+,)+\d+$") )); then
                mapfile -t -d" " ports_list < <(echo "${2}" | tr -s "," " ")
                for port in "${ports_list[@]}"; do
                    if (( port > 0 && port < 65536 )); then
                        PORTS+=( "${port}" )
                    else
                        echo_error "Illegal port ${port} will be ignored."
                    fi
                done
            else
                echo_error "Bad ports ${2}"
                exit 21
            fi
            shift
            shift
            ;;
        -i|--identity)
            if [[ -s $(realpath "${2}") ]]; then
                PRIVATE_KEY=$(realpath "${2}")
            else
                echo_error "${2} not found or empty"
                exit 9
            fi
            shift
            shift
            ;;
        -k|--key-based-ssh)
            SSH=1
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
            if (( SLOW )); then
                echo_error "Scan cannot be fast and slow !"
                exit 18
            fi

            FAST=1

            MAX_THREADS=$(( MAX_THREADS * 3 / 2 ))
            # Fallback to default value
            if ! (( MAX_THREADS )); then MAX_THREADS=16; fi

            # Limit of parallel "sub-threads" per thread
            MAX_SUBTHREADS=$( echo ${MAX_THREADS} | awk '{print(int(sqrt($0)))}' ) # square root of MAX_THREADS
            # Fallback to default value
            if ! (( MAX_SUBTHREADS )); then MAX_SUBTHREADS=4; fi

            shift
            ;;
        -s|--slow)
            if (( FAST )); then
                echo_error "Scan cannot be fast and slow !"
                exit 18
            fi

            SLOW=1

            MAX_THREADS=$(( MAX_THREADS * 2 / 3 ))
            # Fallback to default value
            if ! (( MAX_THREADS )); then MAX_THREADS=16; fi

            # Limit of parallel "sub-threads" per thread
            MAX_SUBTHREADS=$( echo ${MAX_THREADS} | awk '{print(int(sqrt($0)))}' ) # square root of MAX_THREADS
            # Fallback to default value
            if ! (( MAX_SUBTHREADS )); then MAX_SUBTHREADS=4; fi

            shift
            ;;
        -q|--quiet)
            if (( VERBOSE || SUPER_VERBOSE )); then
                echo_error "Cannot be quiet and verbose !"
                exit 22
            fi
            QUIET=1
            # Actual stdout redirection to /dev/null is done afterwards
            # so it does not affects arguments parsing
            shift
            ;;
        -v|--verbose)
            if (( QUIET )); then
                echo_error "Cannot be quiet and verbose !"
                exit 22
            fi
            VERBOSE=1
            shift
            ;;
        -vv|--super-verbose)
            if (( QUIET )); then
                echo_error "Cannot be quiet and verbose !"
                exit 22
            fi
            VERBOSE=1
            SUPER_VERBOSE=1
            shift
            ;;
        -h|--help)
            usage
            exit 5
            ;;
        *)
            if (( ! $(echo "${1}" | grep -cP ${CIDR_PATTERN}) )) || [[ -n ${CIDR} ]]; then
                echo_error "This script takes only one positional argument of the form X.X.X.X/X"
                usage
                exit 6
            fi
            CIDR="${1}"
            mapfile -t RANGE < <(cidr2ips "${CIDR}")
            N_HOSTS=${#RANGE[@]}
            if (( N_HOSTS > MAX_HOSTS || N_HOSTS < 1 )); then
                echo_error "Number of hosts (${N_HOSTS}) should be between 1 and ${MAX_HOSTS}"
                exit 13
            fi
            shift
            ;;
    esac
done

# Checks
if [[ -z "${CIDR}" ]]; then
    echo_error "This script requires one argument of the form X.X.X.X/X"
    usage
    exit 7
fi

if ! (( SSH || EXTENDED || PING )); then
    echo_error "At least one scanning method (-k, -e or -3) is required."
    usage
    exit 24
fi

if (( REFUSED && ! EXTENDED)); then
    echo_error "Ignored option -r (--refused) as it requires extended scanning method (-e, --extended)."
fi

if (( USER && ! SSH )); then
    echo_error "Ignored option -u (--user) as it requires key-based SSH scanning method (-k, --key-based-ssh)."
fi

if (( SSH_PORT != 22 && ! SSH )); then
    echo_error "Ignored option -p (--port) as it requires key-based SSH scanning method (-k, --key-based-ssh)."
fi

if (( QUIET )); then
    if (( ${#OUTPUT[@]} )); then
        # Save original stdout file descriptor
        exec 3>&1 # 4>&2 to save stderr too
        # Redirect stdout to /dev/null (quiet mode)
        exec 1>/dev/null # 2>&1 to redirect stderr too
    else
        echo_error "In quiet mode, an output file must be specified !"
        exit 23
    fi
else
    for file in "${OUTPUT_CSV}" "${OUTPUT_INI}"; do
        if [[ -s "${file}" ]]; then
            echo_error "File ${file} already exists. Overwrite [1|2] ? "
            select ans in yes no; do
                case $ans in
                    "yes")
                        > "${file}"
                        break
                        ;;
                    *)
                        exit 8
                        ;;
                esac
            done
        fi
    done
fi

# Extended ports scan fallback to ssh port if (somehow) not defined.
if ! (( ${#PORTS[@]} )); then
    PORTS+=("${SSH_PORT}")
fi

if (( VERBOSE )); then
    echo "CIDR : ${CIDR} (${N_HOSTS} host(s))"
    echo -e "Scanning methods :\n\t- Key-based SSH on port ${SSH_PORT} with user ${USER}"
    if (( EXTENDED )); then
        echo -ne "\t- extended scan on ports ${PORTS[*]}"
        if (( REFUSED )); then
            echo " (with refused connections)"
        else
            echo
        fi
    fi
    if (( PING )); then echo -e "\t- ICMP scan"; fi
    echo "Timeout : ${TIMEOUT} second(s)"
    if [[ -n "${PRIVATE_KEY}" ]]; then echo "Custom private key : ${PRIVATE_KEY}"; fi
    if (( ${#OUTPUT[@]} )); then echo "Output file(s) : ${OUTPUT[*]}"; fi
    echo "Temporary path : ${TMP_PATH}"
    echo "Temporary file : ${TMP_FILE}"
    echo "Maximum parallel thread(s) : ${MAX_THREADS}"
    echo "Maximum parallel \"sub-thread(s)\" per thread : ${MAX_SUBTHREADS}"
    if (( MAX_THREADS < 16 || MAX_SUBTHREADS < 4 )); then
        echo "[WARNING] MAX_THREADS=${MAX_THREADS} MAX_SUBTHREADS=${MAX_SUBTHREADS} might be slow !"
        echo
    fi
    echo
fi

ETA_SSH=0
ETA_EXT=0
ETA_PING=0

if (( SSH )); then
    ETA_SSH=$(( 2 *  N_HOSTS * TIMEOUT / MAX_THREADS ))
    if (( VERBOSE )); then echo "Key-base SSH scan ETA : ${ETA_SSH} second(s)"; fi
fi

if (( EXTENDED )); then
    ETA_EXT=$(( 2 * N_HOSTS * ${#PORTS[@]} * TIMEOUT / MAX_THREADS / MAX_SUBTHREADS ))
    if (( VERBOSE )); then echo "Extended ports scan ETA : ${ETA_EXT} second(s)"; fi
fi

if (( PING )); then
    ETA_PING=$(( 2 * N_HOSTS * TIMEOUT / MAX_THREADS ))
    if (( VERBOSE )); then echo "ICMP scan ETA : ${ETA_PING} second(s)"; fi
fi

ETA=$(( ETA_SSH + ETA_EXT + ETA_PING ))

echo "ETA : ${ETA} second(s)"

START_TIME=$(date +%s)

if (( SSH )); then
    # Used as filename prefix to order hosts ascending
    COUNT=0
    # Used for guardrail awaits
    PIDS=()
    echo
    echo "[Running key-based SSH scan]"
    for i in "${RANGE[@]}"; do
        COUNT=$(( COUNT+1 ))
        ssh -p "${PORT:-22}" ${PRIVATE_KEY:+-i} ${PRIVATE_KEY:+"${PRIVATE_KEY}"} -o ConnectTimeout="${TIMEOUT:-1}" -o StrictHostKeyChecking=no -o PasswordAuthentication=no -o KbdInteractiveAuthentication=no -o BatchMode=yes "${USER}@${i}" "
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
        " 2>/dev/null > "${TMP_PATH%/}/${COUNT}-${i}-SSH" & #ASYNC
        PIDS+=($!)

        if (( ${#PIDS[@]} >= MAX_THREADS )); then
            # GUARDRAIL AWAIT
            if (( SUPER_VERBOSE )); then echo -n "Guardrail await (${MAX_THREADS} parallel threads)... "; fi
            for pid in "${PIDS[@]}"; do
                wait "${pid}"
            done
            PIDS=()
            if (( SUPER_VERBOSE )); then echo "OK"; fi
        fi
    done
    # AWAIT
    for pid in "${PIDS[@]}"; do
        wait "${pid}"
    done

    # Print to stdout in ascending order
    mapfile -t FILES < <(find "${TMP_PATH%/}" -maxdepth 1 -type f ! -empty -name "*-SSH" 2>/dev/null | sort -V)
    for ext in "${FILES[@]}"; do
        cat "${ext}" 2>/dev/null
        mv "${ext}" "${ext%-SSH}" 2>/dev/null
    done
fi

if (( EXTENDED )); then
    # Used as filename prefix to order hosts ascending
    COUNT=0
    # Used for guardrail awaits
    PIDS=()
    echo
    echo "[Running extended ports scan]"
    for i in "${RANGE[@]}"; do
        COUNT=$(( COUNT+1 ))
        (
            # Skip if host was found previously (scanning method precedence level)
            if [[ ! -s "${TMP_PATH%/}/${COUNT}-${i}" ]]; then
                SUBPIDS=()
                for p in "${PORTS[@]}"; do
                    (
                        NC=$(nc -nzvvw "${TIMEOUT:-1}" "${i}" "${p}" 2>&1)
                        # Must use tmp file because variables defined inside subshell are not accessible outside
                        # WARNING : risk of concurrent write to file
                        if (( $(echo "${NC}" | grep -ciP "${NC_STATUSES}") )); then
                            if [[ ! -s "${TMP_PATH%/}/${COUNT}-${i}-ports" ]]; then
                                # Create list of ports
                                echo -n "${p}" >> "${TMP_PATH%/}/${COUNT}-${i}-ports"
                            else
                                # Append to list of ports
                                echo -n " ${p}" >> "${TMP_PATH%/}/${COUNT}-${i}-ports"
                            fi
                        fi
                    ) & # ASYNC
                    SUBPIDS+=($!)

                    if (( ${#SUBPIDS[@]} >= MAX_SUBTHREADS )); then
                        # GUARDRAIL AWAIT
                        for pid in "${SUBPIDS[@]}"; do
                            wait "${pid}"
                        done
                        SUBPIDS=()
                    fi
                done
                # AWAIT
                for pid in "${SUBPIDS[@]}"; do
                    wait "${pid}"
                done

                # Consolidate final host file and remove tmp ports file
                if [[ -s "${TMP_PATH%/}/${COUNT}-${i}-ports" ]] && ! (( $(grep -c "," "${TMP_PATH%/}/${COUNT}-${i}-ports") )); then
                    cat <(echo "UNKNOWN,${i},") "${TMP_PATH%/}/${COUNT}-${i}-ports" 2>/dev/null | tr -d "\n" > "${TMP_PATH%/}/${COUNT}-${i}-EXT"
                    echo >>"${TMP_PATH%/}/${COUNT}-${i}-EXT"
                    rm "${TMP_PATH%/}/${COUNT}-${i}-ports" 2>/dev/null
                fi
            fi
        ) & # ASYNC
        PIDS+=($!)

        if (( ${#PIDS[@]} >= MAX_THREADS )); then
            # GUARDRAIL AWAIT
            if (( SUPER_VERBOSE )); then echo -n "Guardrail await (${MAX_THREADS} parallel threads)... "; fi
            for pid in "${PIDS[@]}"; do
                wait "${pid}"
            done
            PIDS=()
            if (( SUPER_VERBOSE )); then echo "OK"; fi
        fi
    done
    # AWAIT
    for pid in "${PIDS[@]}"; do
        wait "${pid}"
    done

    # Print to stdout in ascending order
    mapfile -t FILES < <(find "${TMP_PATH%/}" -maxdepth 1 -type f ! -empty -name "*-EXT" 2>/dev/null | sort -V)
    for ext in "${FILES[@]}"; do
        cat "${ext}" 2>/dev/null
        mv "${ext}" "${ext%-EXT}" 2>/dev/null
    done
fi

if (( PING )); then
    # Used as filename prefix to order hosts ascending
    COUNT=0
    # Used for guardrail awaits
    PIDS=()
    echo
    echo "[Running ICMP scan]"
    for i in "${RANGE[@]}"; do
        COUNT=$(( COUNT+1 ))
        # Skip if host was found previously (scanning method precedence level)
        if [[ ! -s "${TMP_PATH%/}/${COUNT}-${i}" ]]; then
            (
                if ping -n -c1 -W"${TIMEOUT:-1}" "${i}" &>/dev/null; then
                    echo "UNKNOWN,${i}" > "${TMP_PATH%/}/${COUNT}-${i}-ICMP"
                fi
            ) & #ASYNC
            PIDS+=($!)

            if (( ${#PIDS[@]} >= MAX_THREADS )); then
                # GUARDRAIL AWAIT
                if (( SUPER_VERBOSE )); then echo -n "Guardrail await (${MAX_THREADS} parallel threads)... "; fi
                for pid in "${PIDS[@]}"; do
                    wait "${pid}"
                done
                PIDS=()
                if (( SUPER_VERBOSE )); then echo "OK"; fi
            fi
        fi
    done
    # AWAIT
    for pid in "${PIDS[@]}"; do
        wait "${pid}"
    done

    # Print to stdout in ascending order
    mapfile -t FILES < <(find "${TMP_PATH%/}" -maxdepth 1 -type f ! -empty -name "*-ICMP" 2>/dev/null | sort -V)
    for icmp in "${FILES[@]}"; do
        cat "${icmp}" 2>/dev/null
        mv "${icmp}" "${icmp%-ICMP}" 2>/dev/null
    done
fi

# Merge all results in ascending order
mapfile -t FILES < <(find "${TMP_PATH%/}" -maxdepth 1 -type f ! -empty 2>/dev/null | sort -V)
if (( ${#FILES[@]} )); then
    cat <(echo hostname,@IP,listening ports) "${FILES[@]}" > "${TMP_FILE}" 2>/dev/null
fi
echo

FOUND=$(wc -l "${TMP_FILE}" 2>/dev/null | cut -d' ' -f1)
if (( $(echo "${FOUND}" | grep -Pc "^\d+$") )) && (( FOUND )); then
    FOUND=$(( FOUND-1 ))
fi
echo  "${FOUND} host(s) found."
echo

if [[ -n "${OUTPUT_INI}" ]] && (( FOUND )); then
    echo -n "[${CIDR}]" | tr -c "[][:alnum:]" "_" >"${OUTPUT_INI}"
    echo >>"${OUTPUT_INI}"

    INI_COUNT=0
    # Iterate over CSV file
    mapfile -t LINES < <(tail +2 "${TMP_FILE}" 2>/dev/null)
    for host in "${LINES[@]}"; do
        # Parse each line
        INI_COUNT=$(( INI_COUNT+1 ))
        INI_HOSTNAME="$(echo "${host}" | cut -d, -f1)"

        # Ensure we keep only the IP address matching the scanned subnet
        mapfile -t IPS_ARRAY < <(echo "${host}" | cut -d, -f2)
        INDEX_IP=0
        while ! (( $(echo "${RANGE[*]}" | grep -cw "${IPS_ARRAY[${INDEX_IP}]}") )) && (( INDEX_IP < ${#IPS_ARRAY[@]} )); do
            INDEX_IP=$(( INDEX_IP+1 ))
        done
        if (( $(echo "${RANGE[*]}" | grep -cw "${IPS_ARRAY[${INDEX_IP}]}") )); then
            INI_IP=${IPS_ARRAY[${INDEX_IP}]}
        else
            echo_error "IP not found for host ${INI_HOSTNAME:-#${INI_COUNT}}"
        fi

        if [[ -n ${INI_HOSTNAME} && -n ${INI_IP} ]]; then
            # Rewrite each line in INI Ansible inventory format
            echo "${INI_COUNT}-${INI_HOSTNAME} ansible_host=${INI_IP}" 2>/dev/null >>"${OUTPUT_INI}"
        else
            echo_error "[INI] Host #${INI_COUNT} ignored due to bad formatting."
        fi
    done
fi

if [[ -n "${OUTPUT_CSV}" ]] && (( FOUND )); then
    mv "${TMP_FILE}" "${OUTPUT_CSV}" 2>/dev/null
fi

if ! (( FOUND )); then
    for output_file in "${OUTPUT[@]}"; do
        rm -f "${output_file}" 2>/dev/null
    done
fi

# FLUSH TMP DIRECTORY
rm -r "${TMP_PATH}" 2>/dev/null

echo "[DURATION] $(( $(date +%s) - START_TIME )) seconds"
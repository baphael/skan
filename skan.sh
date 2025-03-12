#!/usr/bin/env bash

# Simple IPv4 PCRE pattern
CIDR_PATTERN="(\d{1,3}\.){3}\d{1,3}/\d{1,2}"
TMP_FILE="./tmp-skan"

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

Description: Retrieves hostname, IP addresses and listening ports (TCP/UDP) for each SSH-available hosts of a given CIDR.

Usage:	"${SELF}" CIDR
	Press ^C [CTRL+c] to stop

Mandatory argument:
        CIDR : must be a valid subnet (ex : 192.168.1.0/24). A host address will not work (ex : 192.168.1.1/24).

Optional arguments:
    -h, --help              Display this help message and exit.
    -t, --timeout SECONDS   SSH connection timeout. Cannot be below 1 nor above 59. Default is 1.
    -o, --output FILE       Output file.

Examples:
        "${SELF}" 192.168.0.0/24                Scan addresses from 192.168.0.0 to 192.168.0.255. Prints results in STDOUT.
        "${SELF}" -t 2 192.168.0.0/24           Same but with a ssh connection timeout of 2s. Prints results in STDOUT.
        "${SELF}" -o scan.csv 192.168.0.0/24    Same, prints results in both STDOUT and "scan.csv"

Notes:
	WARNING : It is strongly advised against using a small netmask (ex : below /24) as it could take a VERY LONG time...
EOF

}

echo -n "Parse arguments... "
TIMEOUT=1
OUTPUT=""
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

echo hostname,@IP,listening ports | tee "${TMP_FILE}"
for i in $(prips ${CIDR}); do
    ssh -o connectTimeout=${TIMEOUT} -o passwordAuthentication=no ${i} "
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
    " 2>/dev/null | tee -a "${TMP_FILE}"
done

if [[ -z "${OUTPUT}" ]]; then
    rm "${TMP_FILE}"
else
    mv "${TMP_FILE}" "${OUTPUT}"
fi
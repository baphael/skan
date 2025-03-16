# SKAN.SH

Tiny asynchronous bash script for network scanning. It relies on SSH, netcat, ping and a few other built-in bash commands (awk, ps, ss, grep, id, etc.) . It uses dynamic guardrails for parallelization to spare CPU load. 

It takes a CIDR (ex : 192.168.1.0/24) as mandatory positional argument and can take a few optional arguments (see below) to change its behavior.

`skan.sh` offers 3 different scanning methods :
- A mandatory key-based SSH scanning method in which your local host will try a SSH connection on all subnet hosts. For each available host, it will try to fetch hostname, IP addresses and a list of listening ports.
- An optional extended netcat-based scan that will check for opened ports on every hosts based on a given list of ports. For each accessible host, it will fetch a single IP address and a list of listening ports.
- An optional extended ping-based scan. This method operates on a lower-level (L3) and uses ICMP echo request and replies to fetch additional hosts. For each available host, it will only fetch a single IP address.

The wider the subnet range, the longer it will take. Same goes for the list of ports in case of extended netcat-based scan.

Use wisely ;)

## Usage
```
Description:
    Asynchronous subnet scanner.

Usage:
    "${SELF}" [-t|--timeout SECONDS] [-p|--port PORT] [-u|--user USERNAME] [-i|--identity FILE] [-e|--extended PORTS] [-r|--refused] [-3|--ping|--icmp] [-oc|--output-csv FILE] [-oi|--output-ini FILE] [-f|--fast] [-s|--slow] [-v|--verbose] [-vv|--super-verbose] [-vvv --turbo-verbose] [-h|--help] CIDR
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
    -oc, --output-csv FILE  Output CSV-formatted file.
    -oi, --output-ini FILE  Output INI-formatted Ansible inventory file. 

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
    ./${SELF} -oc scan.csv 192.168.0.0/24   Same, prints results in both STDOUT and "scan.csv".

Notes :
    Standard scan retrieves hostname, IP addresses and listening ports (TCP/UDP) but requires SSH key-based access.
    Extended ports scan (-e) do not require any key but will not retrieve hostname.
    Extended ICMP (-3) do not require any key but will not retrieve hostname or ports.
```

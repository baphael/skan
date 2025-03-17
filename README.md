# SKAN.SH

Tiny asynchronous bash script for network scanning. It relies on SSH, netcat, ping and a few other built-in bash commands (mapfile, awk, ps, ss, grep, id, etc.) . It uses dynamic guardrails for parallelization to prevent CPU overload. 

`skan.sh` offers 3 different scanning methods :
- A key-based SSH scanning method in which your local host will try a SSH connection on all subnet hosts. For each available host, it will try to fetch hostname, IP addresses and a list of listening ports.
- An extended netcat-based scan that will check for opened ports on every hosts based on a given list of ports. For each accessible host, it will fetch a single IP address and a list of listening ports.
- A ping-based scan. This method operates on a lower-level (L3) and uses ICMP echo request and replies to fetch additional hosts. For each available host, it will only fetch a single IP address.

It can be used to build an ansible inventory.

Use wisely ;)

## Usage
```
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
    -3, --ping, --icmp      Extended ICMP scan. Includes hosts with L3 ICMP echo response (ping).

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
    Key-based SSH scan retrieves hostname, IP addresses and listening ports (TCP/UDP) but requires a valid key-based access.
    Extended ports scan (-e) do not require any key but will not retrieve hostname.
    Extended ICMP (-3) do not require any key but will not retrieve hostname or ports.
```

Dines
=====

Dines is the definitive answer to DNS testing. It allows the creation of any DNS packet with the possibility to fuzz some fields. Used in shell scripts allows also the creation of fake DNS servers that answer in custom ways.

Usage
-----

This is the help from dines.

    Dines 0.2 - The definitive DNS packet forger.

    Fields with (F) can be fuzzed. (Example --trid F)
    Fields with (R) are repeatable. (Example --answer)
    Fields with (A) are calculated automatically.

    Usage: ./dines <params>

    Params:

    [IP]
    --src-ip <ip>: Source IP (default: local address)
    --dst-ip <ip>: Destination IP

    [UDP]
    --sport <port>: source port
    --dport <port>: destination port (default: 53)

    [DNS]
    --trid <id>: transaction id (F)
    --num-questions <n>: number of questions (A)
    --question <domain>,<type(F)>,<class>: question domain

    --num-ans <n>: number of answers (A)
    --answer(R) <domain>,<type(F)>,<class(F)>,<ttl(F)>,<data>: a DNS answer

    --num-auth <n>: number of authoritative records (A)
    --auth(R) <domain>,<type>,<class(F)>,<ttl(F)>,<data(F)>: a DNS authoritative record

    --num-add <n>: number of additional records (A)
    --additional(R) <domain>,<type(F)>,<class(F)>,<ttl(F)>,<data>: a DNS additional record

    [MISC]
    --num <n>: number of packets (0 means infinite)
    --delay <usec>: delay between packets
    --debug: activate debug
    --help: this help

To generate a question, issue the follogin command:

    sudo ./dines --src-ip 192.168.1.1 --dst-ip 192.168.1.2 --question www.test.com,1,1 --num 1

that asks for domain www.test.com, sending 1 packet only. To generate an answer, one can use the following
command

    sudo ./dines --src-ip 192.168.1.1 --dst-ip 192.168.1.2 --question www.google.com,1,1 --num 1 --answer www.google.com,1,1,256,192.168.1.100 --answer www.google.com,1,1,256,192.168.1.101

The switches related to resource records can be repeated multiple times.

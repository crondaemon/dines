Dines
=====

[![Build Status](https://travis-ci.org/crondaemon/dines.png)](https://travis-ci.org/crondaemon/dines)

Dines is the definitive answer to DNS testing. It allows the creation of any DNS packet with the possibility to fuzz some fields. Used in shell scripts allows also the creation of fake DNS servers that answer in custom ways.

Usage
-----

This is the help from dines.

    Dines 0.3 - The definitive DNS packet forger.

    Fields with (F) can be fuzzed. (Example --txid F)
    Fields with (R) are repeatable. (Example --answer)
    Fields with (A) are calculated automatically.

    Usage: ./dines <params>

    Params:

    [IP]
    --src-ip <ip>: Source IP (default: local address), (F)
    --dst-ip <ip>: Destination IP

    [UDP]
    --sport <port>: source port (A)
    --dport <port>: destination port (default: 53)

    [DNS]
    --txid <id>: transaction id (F)
    --num-questions <n>: number of questions (AF)
    --question <domain>,<type(F)>,<class(F)>: question domain

    --num-ans <n>: number of answers (AF)
    --answer(R) <domain>,<type(F)>,<class(F)>,<ttl(F)>,<data>: a DNS answer

    --num-auth <n>: number of authoritative records (AF)
    --auth(R) <domain>,<type>,<class(F)>,<ttl(F)>,<data>: a DNS authoritative record

    --num-add <n>: number of additional records (AF)
    --additional(R) <domain>,<type(F)>,<class(F)>,<ttl(F)>,<data>: a DNS additional record

    [MISC]
    --num <n>: number of packets (0 = infinite)
    --delay <usec>: delay between packets
    --debug: activate debug
    --verbose: be verbose
    --help: this help


To generate a question, issue the follogin command:

    sudo ./dines --src-ip 192.168.1.1 --dst-ip 192.168.1.2 --question www.test.com,1,1 --num 1

that asks for domain www.test.com, sending 1 packet only. To generate an answer, one can use the following
command

    sudo ./dines --src-ip 192.168.1.1 --dst-ip 192.168.1.2 --question www.google.com,1,1 --num 1 --answer www.google.com,1,1,256,$'\xc0\xa8\01\01' --answer www.google.com,1,1,256,$'\xc0\xa8\01\02'

The switches related to resource records can be repeated multiple times.

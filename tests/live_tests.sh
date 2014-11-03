#!/bin/bash

simple_query()
{
    ./dines --server=20000 --answer www.test.com,a,in,64,1.2.3.4 --num 1 >& /dev/null &
    exp="Received 127.0.0.1:20000 -> 127.0.0.1:20001 txid: 0x1 R NUM=1,1,0,0 [Question:www.test.com/A/IN][Answers:www.test.com/A/IN/64/1.2.3.4]"
    got=`./dines --question www.test.com 127.0.0.1 --dport 20000 --sport 20001 --txid 1 --verbose | grep Received | cut -c 28-`
    if [ "$got" != "$exp" ]
    then
        echo -e "ERRORE:\nexpected:\n$exp\ngot:\n$got\n"
        exit 1
    fi
    echo -n "."
}

fake_num_answers()
{
    ./dines --server=20000 --answer www.test.com,a,in,64,1.2.3.4 --num-ans 2 --num 1 >& /dev/null &
    exp="Received 127.0.0.1:20000 -> 127.0.0.1:20001 txid: 0x1 R NUM=1,2,0,0 [Question:www.test.com/A/IN][Answers:www.test.com/A/IN/64/1.2.3.4]"
    got=`./dines --question www.test.com 127.0.0.1 --dport 20000 --sport 20001 --txid 1 --verbose | grep Received | cut -c 28-`
    if [ "$got" != "$exp" ]
    then
        echo -e "ERRORE:\nexpected:\n$exp\ngot:\n$got\n"
        exit 1
    fi
    echo -n "."
}

# MAIN
make >& /dev/null
if [ "$?" != "0" ]
then
    echo "Compilation failed"
    exit 1
fi

echo -n "Starting live tests"
simple_query
fake_num_answers

echo

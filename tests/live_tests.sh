#!/bin/bash

test_result()
{
    if [ "$2" != "$3" ]
    then
        echo -e "\n\nERROR in $1:\nexpected:\n$2\ngot:\n$3\n"
        exit 1
    fi
    echo -n "."
}

simple_query()
{
    ./dines --server=20000 --answer www.test.com,a,in,64,1.2.3.4 --num 1 >& /dev/null &
    exp="Received 127.0.0.1:20000 -> 127.0.0.1:20001 txid: 0x1 R NUM=1,1,0,0 [Question:www.test.com/A/IN][Answers:www.test.com/A/IN/64/1.2.3.4]"
    got=`./dines --question www.test.com 127.0.0.1 --dport 20000 --sport 20001 --txid 1 --verbose | grep Received | cut -c 28-`
    test_result $FUNCNAME "$exp" "$got"
}

fake_num_answers()
{
    ./dines --server=20000 --answer www.test.com,a,in,64,1.2.3.4 --num-ans 2 --num 1 >& /dev/null &
    exp="Received 127.0.0.1:20000 -> 127.0.0.1:20001 txid: 0x1 R NUM=1,2,0,0 [Question:www.test.com/A/IN][Answers:www.test.com/A/IN/64/1.2.3.4]"
    got=`./dines --question www.test.com 127.0.0.1 --dport 20000 --sport 20001 --txid 1 --verbose | grep Received | cut -c 28-`
    test_result $FUNCNAME "$exp" "$got"
}

no_options()
{
    ./dines >& /dev/null
    test_result $FUNCNAME 1 $?
}

set_gap()
{
    exp="Inter packet gap set to 0 sec, 100 usec"
    got=`./dines --verbose --delay 100 2> /dev/null | grep "Inter packet" | cut -c 28-`
    test_result $FUNCNAME "$exp" "$got"
    exp="Inter packet gap set to 1 sec, 0 usec"
    got=`./dines --verbose --delay 1000000 2> /dev/null | grep "Inter packet" | cut -c 28-`
    test_result $FUNCNAME "$exp" "$got"
}

echo -n "Starting live tests"
simple_query
fake_num_answers
no_options
set_gap

echo "OK"

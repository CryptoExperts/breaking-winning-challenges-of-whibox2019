#!/bin/bash

./tracer

START=0
END=15

for i in $(seq $START $END);
do python dca.py traces_OF_NOp0230_NTr5000_byte$(printf "%02d" $i).tr $i ;
done

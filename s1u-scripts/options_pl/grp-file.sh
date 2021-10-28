#!/bin/bash

while grep 'qtime'  record_all.log &>> record.log
do
        echo -n "" > record_all.log
        sleep 5
done


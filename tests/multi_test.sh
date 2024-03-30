#!/bin/bash
#simple test to see if multithreading works


for file in test1 test2 test3
do
	if ! cmp $file <(bef -c -T0 -i $file | bef -d)
	then
		echo "Multithreaded test for $file failed!"
	fi
done

#!/bin/bash
#tests if raw mode works, using the current fragment size

for file in test1 test2 test3
do
	if ! cmp $file <(bef -c -r 4504 -i $file | bef -d -r 4504)
	then
		echo "raw test for $file failed"
	fi
done

#!/bin/bash
#Tests upgrade flag

for file in test1 test2 test3
do
	if ! cmp <(bef -c -u 0 -i $file | bef -d)
	then
		echo "upgrade for $file failed"
	fi
done

#!/bin/bash
#Tests upgrade flag

for file in test1 test2 test3
do
	if ! cmp $file <(bef -c -L50 -u 0 -i $file | bef -d -L50)
	then
		bef -c -S -L100 -u 0 -i $file -o ${file}.bef
		bef -d -S -L100 -i ${file}.bef -o ${file}.dec
		if ! cmp $file ${file}.dec
		then
			echo "upgrade for $file failed"
		fi
	fi
done

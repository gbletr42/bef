#!/bin/bash
#Tests mmap/seek mode

for file in test1 test2 test3
do
	bef -c -S -i $file -o ${file}.bef
	bef -d -S -i ${file}.bef -o ${file}.dec
	if ! cmp ${file} ${file}.dec
	then
		echo "seek mode for $file failed"
	fi
done

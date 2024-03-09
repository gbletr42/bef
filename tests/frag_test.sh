#!/bin/bash
#Tests fragment numbers of powers of two from 1 to 128


for k in 1 2 4 8 16 32 64 128
do
	for m in 1 2 4 8 16 32 64 128
	do
		for file in test1 test2 test3
		do
			if ! cmp $file <(bef -c -k $k -m $m -i $file | bef -d)
			then
				echo "fragment test for k: $k, m: $m, $file failed!"
			fi
		done
	done
done



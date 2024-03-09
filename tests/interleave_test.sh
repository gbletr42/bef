#!/bin/bash
#Tests if it can successfully interleave our files for up to 256 blocks interleaved, power of 2s

for il_n in 1 2 4 8 16 32 64 128 256
do
	for file in test1 test2 test3
	do
		if ! cmp $file <(bef -c -l $il_n -i $file | bef -d)
		then
			echo "interleave test for $il_n on $file failed!"
		fi
	done
done

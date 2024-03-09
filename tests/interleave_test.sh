#!/bin/bash
#Tests if it can successfully interleave our files for up to 256 blocks interleaved, power of 2s and power of 2s + 1

for il_n in 1 2 3 4 5 8 9 16 17 32 33 64 65 128 129 256 257
do
	for file in test1 test2 test3
	do
		if ! cmp $file <(bef -c -l $il_n -i $file | bef -d)
		then
			echo "interleave test for $il_n on $file failed!"
		fi
	done
done

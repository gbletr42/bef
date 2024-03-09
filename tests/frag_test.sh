#!/bin/bash
#Tests fragment numbers of powers of two from 1 to 128 and that minus 1


for k in 1 2 3 4 7 8 15 16 31 32 63 64 127 128
do
	for m in 1 2 3 4 7 8 15 16 31 32 63 64 127 128 #Eh do I really want 512G in my tests?
	do
		for file in test1 test2 #removed test3 because I *don't want it*
		do
			if ! cmp $file <(bef -c -k $k -m $m -i $file | bef -d)
			then
				echo "fragment test for k: $k, m: $m, $file failed!"
			fi
		done
	done
done



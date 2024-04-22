#!/bin/bash
#Tests block sizes from 1KiB to 1GiB, power of two and power of two plus 1

for ((bsize = 1024; bsize <= $((1024 * 1024 * 1024)); bsize = bsize * 2))
do
	for file in test1 test2 test3
	do
		if ! cmp $file <(bef -c -L50 -l 1 -b $bsize -i $file | bef -d -L50)
		then
			bef -c -S -l 1 -b $bsize -i $file -o ${file}.bef
			bef -d -S -i ${file}.bef -o ${file}.dec
			if ! cmp $file ${file}.dec
			then
				echo "block size test $bsize on $file failed!"
			fi
		fi
		if ! cmp $file <(bef -c -L50 -l 1 -b $(($bsize + 1)) -i $file | bef -d -L50)
		then
			bef -c -S -L100 -l 1 -b $(($bsize + 1)) -i $file -o ${file}.bef
			bef -d -S -L100 -i ${file}.bef -o ${file}.dec
			if ! cmp $file ${file}.dec
			then
				echo "block size test $bsize on $file failed!"
			fi
		fi
	done
done


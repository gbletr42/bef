#!/bin/bash


for parity in jerasure-vand jerasure-cauchy liberasurecode-vand intel-vand intel-cauchy fec-vand
do
	for file in test1 test2 test3
	do
		if ! cmp $file <(bef -c -P $parity -i $file | bef -d)
		then
			echo "parity test for $parity on $file failed!"
		fi
	done
done

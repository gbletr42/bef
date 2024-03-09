#!/bin/bash


for parity in jerasure-vand jerasure-cauchy liberasurecode-vand intel-vand intel-cauchy fec-vand
do
	for file in test1 test2 test3
	do
		bef -c -P $parity -i $file -o $file.bef
		#by default, we should be secure against 4K burst corruption
		dd if=/dev/zero of=$file.bef bs=4K count=1 oseek=4 conv=notrunc

		if ! cmp $file <(bef -d -i $file.bef)
		then
			echo "parity test for $parity on $file failed!"
		fi
	done
done

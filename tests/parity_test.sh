#!/bin/bash


for parity in jerasure-vand jerasure-cauchy liberasurecode-vand intel-vand intel-cauchy fec-vand cm256-cauchy openfec-vand leopard wirehair
do
	for file in test1 test2 test3
	do
		bef -c -P $parity -i $file -o $file.bef
		#by default, we should be secure against 4K burst corruption
		dd if=/dev/zero of=$file.bef bs=4K count=1 seek=4 conv=notrunc status=none

		if ! cmp $file <(bef -d -i $file.bef)
		then
			echo "parity test for $parity on $file failed!"
		fi
	done

	if ! cmp test3 <(bef -c -P $parity -i test3 | ./error | bef -d)
	then
		echo "parity $parity failed error resiliency test!"
	fi
done

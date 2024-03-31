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

	bef -c -P $parity -i test3 -o test3.bef
	for((i = 1; i < 800; i++))
	do
		dd if=/dev/zero of=test3.bef seek=$(($i * 32)) bs=16K count=1 conv=notrunc status=none
	done
	if ! cmp test3 <(bef -d -i test3.bef)
	then
		echo "parity $parity failed error resiliency test!"
	fi
done

#!/bin/bash
#Tests if pipe streams are faithfully reconstructed. Uses cat so that input
#buffers come from pipes as well.
#Also tests if standard file writing is working as expected

for file in test1 test2 test3
do

	if ! cmp $file <(cat $file | bef -c | bef -d)
	then
		echo "$file pipe test failed!"
	fi

	bef -c -i $file -o $file.bef
	bef -d -i $file.bef -o $file.out
	if ! cmp $file $file.out
	then
		echo "$file file test failed!"
	fi

	#Enlarge the file by 1 byte so that it's not evenly aligned
	#Tests whether it can handle uneven data layouts
	dd if=/dev/urandom of=testbyte bs=1 count=1
	cat $file testbyte > ${file}byte

	if ! cmp ${file}byte <(cat ${file}byte | bef -c | bef -d)
	then
		echo "$file + byte pipe test failed!"
	fi

	bef -c -i ${file}byte -o $file.bef
	bef -d -i $file.bef -o $file.out
	if ! cmp ${file}byte $file.out
	then
		echo "$file + byte file test failed!"
	fi
done

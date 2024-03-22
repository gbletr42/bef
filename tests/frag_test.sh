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

#Test very large k and m values with wirehair, almost to max
#k caps at 64000 for wirehair, m at 65535
for k in 255 256 511 512 1023 1024 2047 2048 4095 4096 8191 8192 16383 16384 32767 32768 63999 64000
do
	for m in 255 256 511 512 1023 1024 2047 2048 4095 4096 8191 8192 16383 16384 32767 32768 65534 65535
	do
		for file in test1 test2
		do
			if ! cmp $file <(bef -c -P wirehair -k $k -m $m -i $file | bef -d)
			then
				echo "fragment test for k: $k, m: $m, $file failed!"
			fi
		done
	done
done



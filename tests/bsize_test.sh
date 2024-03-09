#!/bin/bash
#Tests block sizes from 1KiB to 1GiB, power of two

for bsize in 1K 2K 4K 8K 16K 32K 64K 128K 256K 512K 1M 2M 4M 8M 16M 32M 64M 128M 256M 512M 1G
do
	for file in test1 test2 test3
	do
		if ! cmp $file <(bef -c -b $bsize -i $file | bed -d)
		then
			echo "block size test $bsize on $file failed!"
		fi
	done
done


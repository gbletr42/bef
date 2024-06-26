#!/bin/bash

for hash in sha1 sha256 sha512 sha3 blake2s blake2b blake3 md5 crc32 crc32c xxhash
do
	for file in test1 test2 test3
	do
		if ! cmp $file <(bef -c -H $hash -i $file | bef -d)
		then
			echo "hash test for $hash on $file failed!"
		fi
	done
done

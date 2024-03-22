#!/bin/bash
#Removes/inserts a fragment's worth of data from test3 and sees if the tool is able to reconstruct it faithfully.

bef -c -i test3 -o test3.bef
dd if=test3.bef of=test3.bef.tmp bs=4K count=1023 status=none
dd if=test3.bef bs=4M iseek=1 status=none >> test3.bef.tmp

if ! cmp test3 <(bef -d -i test3.bef.tmp)
then
	echo "deletion test failed!"
fi

dd if=test3.bef of=test3.bef.tmp bs=4K count=1024 status=none
dd if=/dev/zero of=test3.bef.tmp bs=4K oseek=1024 count=1 status=none
dd if=test3.bef bs=4M iseek=1 status=none >> test3.bef.tmp

if ! cmp test3 <(bef -d -i test3.bef.tmp)
then
	echo "insertion test failed!"
fi

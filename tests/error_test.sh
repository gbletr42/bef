#!/bin/bash
#Simple function that tests the error resiliency of the format by inserting errors at random offsets
#In total 12 errors are placed at predefined offsets that are wide enough apart it shouldn't cause problems.


bef -c -i test3 -o test3.bef
dd if=/dev/urandom of=test3.bef bs=4K count=1 oseek=125681 conv=notrunc
dd if=/dev/urandom of=test3.bef bs=4K count=1 oseek=226161 conv=notrunc
dd if=/dev/urandom of=test3.bef bs=4K count=1 oseek=243984 conv=notrunc
dd if=/dev/urandom of=test3.bef bs=4K count=1 oseek=110031 conv=notrunc
dd if=/dev/urandom of=test3.bef bs=4K count=1 oseek=136749 conv=notrunc
dd if=/dev/urandom of=test3.bef bs=4K count=1 oseek=176266 conv=notrunc
dd if=/dev/urandom of=test3.bef bs=4K count=1 oseek=130362 conv=notrunc
dd if=/dev/urandom of=test3.bef bs=4K count=1 oseek=212750 conv=notrunc
dd if=/dev/urandom of=test3.bef bs=4K count=1 oseek=190019 conv=notrunc
dd if=/dev/urandom of=test3.bef bs=4K count=1 oseek=162467 conv=notrunc
dd if=/dev/urandom of=test3.bef bs=4K count=1 oseek=197391 conv=notrunc
dd if=/dev/urandom of=test3.bef bs=4K count=1 oseek=232946 conv=notrunc
if ! cmp test3 <(bef -d -i test3.bef)
then
	echo "failed error resiliency test!"
fi

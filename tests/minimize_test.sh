#!/bin/bash
#tests if minimizing works, by giving a big block size and seeing if test1 and test2 outputs are also big (>16M)

BSIZE="32M"

for file in test1 test2
do
	bef -cM -b $BSIZE -i $file -o ${file}.bef
	SIZE=$(cat ${file}.bef | wc -c)

	if [[ $SIZE -gt 16777216 ]]
	then
		echo "Minimize test created big file for $file"
	fi

	if ! cmp $file <(bef -d -i ${file}.bef)
	then
		echo "Minimize test failed for $file"
	fi
done

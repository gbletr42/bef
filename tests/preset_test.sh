#!/bin/bash
#tests each available preset

for preset in standard share archive paranoid
do
	for file in test1 test2 test3
	do
		if ! cmp $file <(bef -c -p $preset -i $file | bef -d)
		then
			echo "preset test for $preset, $file failed"
		fi
	done
done

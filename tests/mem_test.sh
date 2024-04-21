#!/bin/bash
#Tests if bef crashes if attempting to use a ridiculous amount of memory

bef -c -u 1024G -i test1 -o /dev/null && echo "memory test failed"

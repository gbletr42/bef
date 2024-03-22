#!/bin/bash
#Prepares necessary files for tests
#Currently it is a 128KiB, 4MiB, 4GiB set of files containing random data

dd if=/dev/urandom of=test1 bs=128K count=1 status=none
dd if=/dev/urandom of=test2 bs=4M count=1 status=none
dd if=/dev/urandom of=test3 bs=4M count=1024 status=none

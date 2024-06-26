#!/bin/bash
#
#Yes, the tests are in bash, because this is the simplest way of testing if the
#software works. Dealing with unit tests or whatever in C seems like it'd be way
#more painful. These set of scripts assume that some commands are present.

#Check if bef is in PATH
if ! which bef
then
	exit -1
fi

bash prepare_tests.sh
bash mem_test.sh
bash io_test.sh
bash multi_test.sh
bash minimize_test.sh
bash seek_test.sh
bash upgrade_test.sh
bash raw_test.sh
bash preset_test.sh
bash insertion_test.sh
bash bsize_test.sh
bash frag_test.sh
bash hash_test.sh
bash interleave_test.sh
bash parity_test.sh
bash cleanup_tests.sh



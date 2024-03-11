# Preliminary
We are going to be comparing this tool against 3 others

* [zfec](https://github.com/tahoe-lafs/zfec)
* [par2cmdline](https://github.com/Parchive/par2cmdline)
* [par2cmdline-turbo](https://github.com/animetosho/par2cmdline-turbo)

Each of these are in their own right useful tools for creating erasure coded backups, so I'll briefly describe what they do and their benefits/drawbacks.

* zfec is a very simple python/C application that splits the input into 'blocks', primary being the original and secondary being the parity, and is able to reconstruct the original input with only a subset of the output blocks. It does not have any integrity checking and as such any corruption within any of the primary blocks (or secondary if primary is missing) will lead to a corrupted output. Thus, users are expected to keep hashes in addition to the set of block files.
* par2cmdline is the older and more well known tool for making erasure coded backups. Designed to cope with the unreliability of Usenet, it computes a Reed Solomon Matrix from the input file[s] and stores the output recovery blocks in special par2 files. Thus, it doesn't modify the original data and allows you to corrupt any location in the original data as long as you have the requisitie number of recovery blocks to come back from your error. It's very slow and not performance oriented, and also uses OpenMP to be multithreaded.
* par2cmdline-turbo is a performance-oriented fork of par2cmdline, using modern CPU extensions and implements real multithreading support (rather than OpenMP). It is significantly faster than mainline par2cmdline.

# Benchmark
General details of the benchmark will be that the test file will be 1GiB of random data, the location will be in /tmp/ to minimize any bias from the storage device or filesystem, and that each tool shall get around 25% redundancy. The specific series of commands to do the test are listed below. The specific hardware details of the machine running the tests are that it is a Dell Latitude 7490, i5-7300U, with 16GB of RAM.

bef encode: bef -c -k 4 -m 1 -i test -o test.bef  
bef corruption: dd if=/dev/zero of=test.bef bs=4K count=1 oseek=1 conv=notrunc  
bef decode: bef -d -i test.bef -o test.dec  

zfec encode: zfec -m 5 -k 4 test  
zfec corruption: rm test.0\_5.fec  
zfec decode: zunfec \*.fec -o test2  

par2cmdline[-turbo] encode: par2 c -r25 test  
par2cmdline[-turbo] corruption: dd if=/dev/zero of=test bs=4K count=1 conv=notrunc  
par2cmdline[-turbo] decode: par2 r test  

Below is the table detailing time for encode and decode for each of the 4 tools. The original par2cmdline is last for a reason ;).

| Program | Encode | Decode |
| ------- | ------ | ------ |
| bef | 2.35s | 0.975s |
| zfec | 4.52s | 2.40s |
| par2cmdline-turbo | 20.43s | 7.86s |
| par2cmdline | 159.52s | 20.58s |

As one can see, my tool is significantly faster than every other option. However, it should be noted that par2 offers significantly greater protection against corruption as it can repair against any arbitrary corruption, rather than either my tool or zfec, which can only repair corruption per block or can only work with complete erasure of blocks respectively.

# Conclusions
My conclusions from these benchmarks is that if you want a fast and capable erasure coding tool and are fine with the inherent limitations in the format, pick my tool. Otherwise, if you want maximal protection at the cost of speed/streamability, pick par2cmdline-turbo.

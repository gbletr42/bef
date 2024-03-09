# WARNING
**This software package has not been extensively battle tested in the real world. While your data is *probably* safe, there may be data eating bugs hiding**

# Description
Block Erasure Format is a file utility and file format designed to fix the pain points I've personally had with existing utilities. It has a nice and easy to use interface, at least according to me, it is simple with minimal overhead, and it is very fast. It is also designed to be modular and extensible, with modular hash and parity library backends. The file format is fully streamable, meaning it does not need to have a seekable file to work, so you can just pipe data right in from say tar. It is finally a very small piece of software, only around 1.5 klocs, so it should be readily auditable and forkable.

# What even are erasure codes?
Erasure codes are a type of error correction codes that can be applied to a set of k input symbols (such as k blocks of data) and output k+n output symbols. You can lose any n symbols from the output before you are unable to reconstruct the original input, providing you with significant protection against corruption.

These are used in situations where there can be significant burst corruption, where a large sequential number of bytes are corrupted, and you don't want to lose all your data. Examples of existing technologies that use this are CDs, DVDs, BDs, HDDs, and SSDs, each having failure modes that require it.

# Format
The format is designed to be simple, although it was quite a bit more complicated earlier in the design process. It is based on the concept of a 'block' of data, which is then split into data and parity fragments by the parity backend. Then these fragments are hashed and interleaved with fragments from n other blocks. A simple diagram is below. M is the last fragment number, which also are the parity fragments.

\[B1-F1\] -> \[B2-F1\] -> \[B3-F1\] -> \[B1-F2\] -> \[...\] -> \[B1-FM\] -> \[B2-FM\] -> \[B3-FM\]

This format is pretty similar to the one used in CDs, but unlike that standard bef is fully variable in how it can follow this format. The number of parity and data fragments, the number of blocks to interleave, the block size, the hash, and the specific parity library providing the erasure codes are all customizable and stored in a header right before the data.

Currently, that is all the information stored in the header, making it only 20 bytes large. However, we want to be able to extend the format in the future and ensure we are getting a good header. So the header has additional operation flags and padding to make it 64 bytes, is duplicated in case it corrupts, and a hash is available to check its integrity. In the worst case, we can omit the header entirely if we already know all information.

I believe this format is, or at least can be with the right settings, highly resilient to burst corruption. Under default settings, it can handle in the worst case one burst of slightly larger than 8KiB per 192KiB. It is however not resilient to random noise, and will corrupt beyond repair in such environments. Luckily environments with such ambient noise in computing are rare, outside of telecommunications.

# What will it build on?
I have built and tested it against x86-64 and x86, on Debian Bookworm and Alpine Linux 3.19, and the results are that it _seems_ to work on both architectures!

Only Linux is supported for now, it is not cross platform.

# Dependencies
Mandatory dependencies to build this package are

- [xxhash](https://github.com/Cyan4973/xxHash)

There are some additional optional dependencies as well

- [BLAKE3](https://github.com/BLAKE3-team/BLAKE3/tree/master/c) for BLAKE3
- [OpenSSL](https://www.openssl.org) for SHA1, SHA256, SHA3, BLAKE2S, and MD5
- [Zlib](https://github.com/madler/zlib) for CRC32
- [liberasurecode](https://github.com/openstack/liberasurecode) for Jerasure, ISA-L, and its own native implementation of Reed solomon codes, support.

Most of these are provided by distributions, except for liberasurecode and BLAKE3's C interface.

# Benchmarks
These benchmarks are done on a Dell Latitude 7490, i5-7300U, 16GB of RAM, . The test file is 1GiB of random data recently read with cat right before the benchmark, and also in /tmp/. The software packages being compared are mine's truly, zfec, and par2cmdline (you'll see why its last ;) )

| Run  | bef  | zfec | par2 |
| ---- | ---- | ---- | ---- |
| encode time (SSD) | 2.17s | 17.23s | 41.88s |
| decode time (SSD) | 1.06s | 1.72s | 0s (doesn't touch original data) |
| decode time + corruption (SSD) | 4.39s | 1.79s | 21.62s |
| encode time (tmpfs) | 2.05s | 11.64s | 42.90s |
| decode time (tmpfs) | 1.12s | 1.46s | 0s (doesn't touch original data) |
| decode time + corruption (tmpfs) | 1.11s | 1.44s | 19.92s |

As one can see, bef is significantly faster than each option except zfec when it comes to decoding a corrupted fragment or two on disk. Par2 is very very slow, and that's very much one of the main reasons I made this software.

# Future Support/Compatibility
With v0.1, the binary format is now frozen in place and will NEVER change. It can still be extended via use of flags and padding, but it will never be unable to be read by future versions of bef. Thus I guarantee full backward and partial forward compatibility, with the caveat that, since I am not an oracle, the forward compatibility is limited to the subset of features available at that given version, and thus incompatible with newer features extended to the binary format.

However, the CLI is not frozen in place, but I will try my hardest to never modify, and the internal library API/ABI has no guarantees of any compatibility with any other version.

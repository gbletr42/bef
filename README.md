# WARNING
**This software package has not been extensively battle tested in the real world. While your data is *probably* safe, there may be data eating bugs hiding**

# Description
Block Erasure Format is a file utility and file format designed to fix the pain points I've personally had with existing utilities. It has a nice and easy to use interface, at least according to me, it is simple with minimal overhead, and it is very fast. It is also designed to be modular and extensible, with modular hash and parity library backends. The file format is fully streamable, meaning it does not need to have a seekable file to work, so you can just pipe data right in from say tar.

# What even are erasure codes?
Erasure codes are a type of error correction codes that can be applied to a set of k input symbols (such as k blocks of data) and output k+n output symbols. You can lose any n symbols from the output before you are unable to reconstruct the original input, providing you with significant protection against corruption.

These are used in situations where there can be significant burst corruption, where a large sequential number of bytes are corrupted, and you don't want to lose all your data. Examples of existing technologies that use this are CDs, DVDs, BDs, HDDs, and SSDs, each having failure modes that require it.

# Examples
For an example of how to use bef using the in built command line tool, see below

```
#To create a file/stream, use the -c argument. To decode it, use -d.
#Likewise, to choose input and/or output, use the -i/-o arguments.
bef -c -i file -o file.bef
bef -d -i file.bef -o file

#By default the input is STDIN and the output is STDOUT, so you can use bef in a series of pipes
#For example, here's how we can send files between two computers using netcat, tar, zstd, and bef.

#Sender
tar c dir | zstd | bef -c | nc receiver 7000

#Receiver
nc -l -p 7000 | bef -d | unzstd | tar x
```

More information can be found in the manpage/help argument.

# Format
The format is designed to be simple, although it was quite a bit more complicated earlier in the design process. It is based on the concept of a 'block' of data, which is then split into data and parity fragments by the parity backend. Then these fragments are hashed and interleaved with fragments from n other blocks. A simple diagram is below. M is the last fragment number, which also are the parity fragments.

\[B1-F1\] -> \[B2-F1\] -> \[B3-F1\] -> \[B1-F2\] -> \[...\] -> \[B1-FM\] -> \[B2-FM\] -> \[B3-FM\]

This format is pretty similar to the one used in CDs, but unlike that standard bef is fully variable in how it can follow this format. The number of parity and data fragments, the number of blocks to interleave, the block size, the hash, and the specific parity library providing the erasure codes are all customizable and stored in a header right before the data.

Currently, that is all the information stored in the header, making it only 20 bytes large. However, we want to be able to extend the format in the future and ensure we are getting a good header. So the header has additional operation flags and padding to make it 64 bytes, is duplicated in case it corrupts, and a hash is available to check its integrity. In the worst case, we can omit the header entirely if we already know all information.

I believe this format is, or at least can be with the right settings, highly resilient to burst corruption. Under default settings, it can handle in the worst case one burst of slightly larger than 16KiB per 320KiB. It is however not resilient to random noise, and will corrupt beyond repair in such environments. Luckily environments with such ambient noise in computing are rare, outside of telecommunications.

## Limitations
This format does NOT offer full parity with every other fragment in the stream, rather each block is erasure coded individually into block fragments and interleaved. This means that a given block can be corrupted by one or more burst errors of relatively small size (a little over 16KiB by default is a probability game). A really unlucky burst could corrupt multiple block fragments such that it makes a given block unrecoverable.

Currently, by default each block is 64KiB in size, erasure coded with 15 data fragments and 1 parity, and interleaved 5 at a time. This means the absolute worst case burst size that can lead to a given block becoming unrecoverable is a little larger than 16KiB, as, assuming each fragment is 4KiB, it could do something like this

1 byte corrupts frag x of block n, 4096 bytes corrupts frag x of block n+1, 4096 bytes corrupts frag x of block n+2, 4096 bytes corrupts frag x of block n+3, 4096 bytes corrupts frag x of block n+4, 1 byte corrupts frag x+1 of block n.

And as such _two_ fragments for block n were corrupted, when by default we only have 1 parity. The more fragments you interleave, the closer and closer you get to achieving a burst size equal to the total size of parities in the whole set of interleaved block fragments. In addition, the more parity fragments you generate, the closer and closer you get to that limit. Specifically, you can approximate the burst size ratio using this mathematical formula, where B is the fragment size, m is the number of parity fragments, k is the number of data fragments, and N is the number of blocks interleaved. Fragment size can be approximated by the ratio $\frac{B}{k}$, where B is the block size and k is the number of data fragments. Parity fragments do not impact the fragment size.

$\frac{B(m-1+(N-1)m) + 2}{NB(k+m)}$

As one can see, increasing either m or N will bring you closer to the limit of $\frac{m}{k+m}$, and increasing both m and k will lead to you being closer to that limit if N is constant. Thus if one wants a greater assurance of data integrity, they should increase m, N, or both.

This is a fundamental limitation in the format, so if you need maximal assurance your data will be safe with a giant burst of say a gigabyte, I recommend using par2cmdline instead as it offers those assurances.

# What will it build on?
I have built and tested it against x86-64 and x86, on Debian Bookworm and Alpine Linux 3.19, and the results are that it _seems_ to work on both architectures!

Only Linux is supported for now, it is not cross platform.

There are also packages maintained by me at the AUR for those using Arch Linux.

# Dependencies
Mandatory dependencies to build this package are

- [xxhash](https://github.com/Cyan4973/xxHash)

There are some additional optional dependencies as well

- [BLAKE3](https://github.com/BLAKE3-team/BLAKE3/tree/master/c) for BLAKE3
- [OpenSSL](https://www.openssl.org) for SHA1, SHA256, SHA3, BLAKE2S, and MD5
- [Zlib](https://github.com/madler/zlib) for CRC32
- [liberasurecode](https://github.com/openstack/liberasurecode) for Jerasure, ISA-L, and its own native implementation of Reed solomon codes, support.

Most of these are provided by distributions, except for liberasurecode and BLAKE3's C interface.

# Comparison to other tools
Please see [Comparison.md](Comparison.md) for a detailed comparison between this, zfec, par2cmdline, and par2cmdline-turbo.

# Future Support/Compatibility
With v0.2, the binary format is now frozen in place and will NEVER change. It can still be extended via use of flags and padding, but it will never be unable to be read by future versions of bef. Thus I guarantee full backward and partial forward compatibility, with the caveat that, since I am not an oracle, the forward compatibility is limited to the subset of features available at that given version, and thus incompatible with newer features extended to the binary format.

However, the CLI is not frozen in place, but I will try my hardest to never modify, and the internal library API/ABI has no guarantees of any compatibility with any other version.

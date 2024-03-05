# DISCLAIMER
**THIS IS A WIP SOFTWARE PACKAGE, ONLY USE IF YOU'RE FINE LOSING ALL YOUR DATA**

**THERE IS NO GUARANTEEE OF BACKWARDS OR FORWARDS COMPATIBILITY, DO NOT USE IN PRODUCTION OR ON YOUR FAMILY PHOTOS**

# Description
Okay, now that that scary disclaimer is over, I'd like to introduce what this software is. This software package is an attempt to create a flexible, useable erasure coding tool through a custom designed binary format. It was designed out of frustrations with existing tools, and is designed to fix those pain points. Sadly, as of right now, it currently has some other major pain points that need resolution :(.

It is not explicitly designed to be secure or free of stuff like buffer overflows and null pointer dereference. I mean, I don't want these things and so my code at least isn't swimming in them to my knowledge, but I don't have confidence in it.

# Dependencies
Mandatory dependencies to build this package are

- [liberasurecode](https://github.com/openstack/liberasurecode)
- [xxhash](https://github.com/Cyan4973/xxHash)

There are some additional optional dependencies as well, currently used to provide additional hash algorithms

- [BLAKE3](https://github.com/BLAKE3-team/BLAKE3/tree/master/c)
- [OpenSSL](https://www.openssl.org)
- [Zlib (CRC32)](https://github.com/madler/zlib)

Most of these are provided by distributions, except for liberasurecode.

# Format
The format is a little complicated and a little simple. Due to limitations in liberasurecode, I could only have at most 32 'fragments' to divide the data. Sadly, that was not going to cut it...

So to work around these limitations, I designed this format. To describe it from a high level, each file is made up of a number of segments, which are each made up of a number of 'blocks' of defined size, which each are subdivided into a number of 'fragments'. Currently the data blocks are layed out linearly as they come from the backend parity library, and the parities are randomly distributed after the blocks. To give a short diagram, with fragments 1-3 being data and fragment 4 being parity. X is a random block somewhere in the file.

\[B1-F1\] -> \[B1-F2\] -> \[B1-F3\] -> \[BX-F4\] -> \[B2-F1\] -> \[...\]

This has some current limitations in design.

1. Any unlucky burst corruption of bytes greater than the size of a fragment header could wipe out data fragments when you could just have 1 parity somewhere or another. This could be somewhat solved by interleaving n blocks worth of data fragments, but that extension to the format has not been implemented.
2. Burst corruption of bytes greater than m fragments, where m is the number of parity fragments, that happen in a range of data fragments, will corrupt the stream. Like before, this could be solved through interleaving data fragments.
3. There is an extensive performance hit to randomly swapping the parities at the moment, which make it very expensive to do on IO-constrained storage devices such as HDDs, requiring either the file be in the FS Dirty Cache or on a faster device like a SSD. Not sure if this problem is solvable or not, at least not without a lot of memory.

So in general, if these problems persist in the future, I'd recommend another solution if any of them impact you.

# Other Solutions
I feel like I should give a heads up to other solutions and their benefits/flaws

- [par2cmdline](https://github.com/Parchive/par2cmdline) is probably the most well known alternative. It's flaws is that it is extremely slow. Compared to my WIP utility on a 1GIB file with a block/fragment size of 32768 (32k) bytes, and a parity ratio of 1/16, on my laptop SSD with my laptop processor (i5-7300U), it is 114 times slower (took 745.71 seconds) compared to mine (took 6.56 seconds) and also made the computer rather warm. The file was of course in cache and the specific backend library was Intel's ISA-L library through liberasurecode.
- [zfec](https://github.com/tahoe-lafs/zfec) is not nearly as known, but is a good alternative and my recommended solution to anyone reading this. It is significantly faster than par2cmdline with the limitation that it can only support up to 256 blocks/fragments in total. Compared to my solution, on that same 1GiB file with 256 total share and 240 required share (4MiB per fragment/share), it is 4x slower taking 21.11 seconds compared to 5.53 seconds.

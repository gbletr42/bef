/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Header file for bef library code
 * Copyright (C) 2024 gbletr42
 *
 * This program is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program. If not, see <https://www.gnu.org/licenses/>.
 */

#ifndef BEF_H
#define BEF_H	1

/* Our third party libraries */
#include "../config.h"
#define _FILE_OFFSET_BITS 64 //Make off_t 64 bits
#include <stdint.h>
#include <stddef.h>
#include <sys/types.h>

/* Our sexy magic number ( ͡° ͜ʖ ͡°) */
static const char *bef_magic = "BEFBABE";

/* Our error codes
 * In general, all error codes are negative, and all positive returns are errors
 * being propagated back from underlying libraries if available. When an error
 * is found, it is generally propagated back up if it can't be handled by the
 * library.
 */
#define BEF_ERR_INVALSIZE	1 //Invalid size of something or another
#define BEF_ERR_INVALINPUT	2 //Invalid input of something or another
#define BEF_ERR_NEEDMORE	3 //Needs more of something, say parity
#define BEF_ERR_OVERFLOW	4 //Something overflowed when it shouldn't have
#define BEF_ERR_READERR		5 //A read() command failed to do as expected
#define BEF_ERR_WRITEERR	6 //A write() command failed to do as expected
#define BEF_ERR_INVALHASH	7 //A digest is not equal to what was given
#define BEF_ERR_NULLPTR		8 //Something's NULL and it ain't needed
#define BEF_ERR_INVALHEAD	9 //Header's funky and wonky

/* Placeholder error values, to be replaced with more descriptive errors */
#define BEF_ERR_OPENSSL		1453 //Error in OpenSSL library


/* Default block size in bytes
 * Sized according to relative benchmarks for a 1GiB chunk of memory and various
 * different k and m values, in addition to desiring a small fragment size to
 * ward off corruption. May replace with an algorithm to automatically select an
 * ideal block size. This would protect 4KiB per fragment, with default
 * parities.
 */
#define BEF_BSIZE 65536

/* Default data and parity fragment ratios, just out of personal preference, I'd
 * like to lose at least 5% of the file on average before I give up and call it
 * quits.
 */
#define BEF_K_DEFAULT	15
#define BEF_M_DEFAULT	1

/* Max hash size in header in bytes */
#define BEF_HASH_SIZE 32

/* Our various backends */
#define BEF_BACKEND_LIBERASURECODE	1

/* Our various hash types */
#define BEF_HASH_NONE		1 //Living life dangerously
#define BEF_HASH_SHA1		2
#define BEF_HASH_SHA256		3
#define BEF_HASH_SHA3		4
#define BEF_HASH_BLAKE2S	5
#define BEF_HASH_BLAKE3		6 //Best general-use cryptographic hash
#define BEF_HASH_MD5		7
#define BEF_HASH_CRC32		8
#define BEF_HASH_XXHASH		9 //Default, fast and reasonably secure
#define BEF_HASH_DEFAULT	BEF_HASH_XXHASH

/* Our parity types, currently just copied liberasurecode
 * Haven't used/benchmarked non reed solomon codes */
//#define BEF_PAR_XOR	1 //Basic Flat XOR
#define BEF_PAR_J_V_RS	2 //Jerasure Vandermonde Reed Solomon
#define BEF_PAR_J_C_RS	3 //Jerasure Cauchy Reed Solomon
#define BEF_PAR_LE_V_RS	4 //liberasurecode Software Vandermonde Reed Solomon
#define BEF_PAR_I_V_RS	5 //Intel ISA-L Vandermonde Reed Solomon
#define BEF_PAR_I_C_RS	6 //Intel ISA-L Cauchy Reed Solomon
//#define BEF_PAR_SHSS	7 //NTT's SHSS erasure coding algorithm
//#define BEF_PAR_PHAZR	8 //Phazr.IO's erasure coding algorithm
#define BEF_PAR_F_V_RS	9 //zfec's libfec Software Vandermonde Reed Solomon

/* I find that, unless it's exceptionally large number of fragments, zfec's
 * modified libfec seems to be by far the fastest
 */
#define BEF_PAR_DEFAULT	BEF_PAR_F_V_RS

/* Custom types */
typedef uint8_t bef_hash_t;
typedef uint8_t bef_par_t;

/* Our real header, contains all necessary info */
struct bef_real_header {
	uint64_t	nbyte; //Total number of bytes in each fragment
	uint32_t	seed; //Random seed for parity shuffling
	uint16_t	k; //Total number of data fragments per block
	uint16_t	m; //Total number of parity fragments per block
	bef_par_t	par_t; //Parity type for all blocks
	uint8_t		pad1[3];
};

/* Our sexy header */
struct bef_header {
	char			magic[7]; //Our magic number babe ^_^
	bef_hash_t		hash_t; //hash type for WHOLE FILE
	uint8_t			hash[BEF_HASH_SIZE]; //hash of header
	struct bef_real_header	header;
	struct bef_real_header	header_b; //backup header
};

/* Block Header struct, what follows after is the body of the block */
struct bef_frag_header {
	uint64_t	pbyte; //For when bytes + header < nbyte
	uint8_t		hash[BEF_HASH_SIZE]; //hash of fragment body
};

/* Generalized hash function call, makes life easier. Takes in a given input of
 * nbyte bytes and fills the given array with it. It is assumed the array is
 * BEF_HASH_SIZE bytes long, so passing a bad array is very bad.
 *
 * error codes not yet defined, but will return 0 when successful
 */
int bef_digest(const char *input, size_t nbyte, uint8_t *output,
	       bef_hash_t hash_t);

/* Generalized erasure coding encoding function call, to once again make life
 * easier. Takes in a ratio of data symbols and repair symbols, in addition to
 * an input buffer of inbyte size and generates two output buffer arrays,
 * data of k data buffers frag_len long, and parity of m parity buffers frag_len
 * long. It is the caller's responsibility to allocate the two arrays. The
 * function by default allocates the buffers, and it is also the caller's
 * responsibility to free them with bef_encode_free().
 *
 * error codes not yet defined, but will return 0 when successful
 */
int bef_encode_ecc(const char *input, size_t inbyte, char **data,
		   char **parity, size_t *frag_len, int k, int m,
		   bef_par_t par_t);

/* Frees the data structures allocated by bef_encode_ecc */
void bef_encode_free(char **data, char **parity, int k, int m);

/* Generalized erasure code decoding function. It takes in an array of
 * fragments, each fragment's size in byte, and outputs the decoded result to
 * the given output buffer. Like before, k and m need to be explicitly given.
 * Like the encode call, the output will be allocated by the function and it is
 * the caller's responsibility to free it with bef_decode_free().
 *
 * error codes not yet defined, but will return 0 when successful
 */
int bef_decode_ecc(char **frags, uint16_t frag_len, size_t frag_b,
		   char **output, size_t *onbyte, int k, int m,
		   bef_par_t par_t);

/* Frees the output buffer from bef_decode_ecc(). Of course you could also just
 * free() it yourself ;)
 */
void bef_decode_free(char *output);

/* Main Function that takes in a fileno and outputs in another given fileno the
 * formatted file. Also given are the options for the construction, the parity
 * type and amount thereof, hash type, segment and desired block size (will
 * attempt to approximate).
 *
 * If nblock is 0, there will only be one segment with an unlimited number of
 * blocks. Do note that segments are fantastical constructions aren't actually
 * represented in the metadata, so there can thereotically be an unlimited
 * number of segments, each with their own independent erasure codes, each of
 * approximate size num_blocks * bsize (real size is determined at creation).
 *
 * If bsize is set to 0, it will default to BEF_BSIZE
 *
 * If par_t is set to 0, it will default to BEF_PAR_DEFAULT
 *
 * If hash_t is set to 0, it will default to BEF_HASH_DEFAULT
 *
 * If k is set to 0, it will default to BEF_K_DEFAULT
 * If m is set to 0, it will default to BEF_M_DEFAULT
 *
 * Due to limitations in design, the output file MUST be seekable, so as to
 * shuffle the parities.
 *
 * error codes not yet defined, but will return 0 when successful
 */
int bef_construct(int input, int output,
		  bef_par_t par_t, uint16_t k, uint16_t m, bef_hash_t hash_t,
		  uint32_t nblock, uint64_t bsize);

/* Main function that does the inverse of the above function, it decodes my
 * shitty format into usable data again. Comparatively speaking at least, it has
 * a much nicer function call than the other one. Unlike the above, there are no
 * options for deconstruction at the moment, it just werks.
 *
 * Like the construct method, my file format has the sorry limitation of needing
 * to be seekable to work, and as such you _cannot_ use STDIN as the input. Work
 * may be done in the future to support an alternative deconstruction mode that
 * blocks until it finds the required parity fragment, but as of now it'll just
 * not werk if given STDIN due to it's assumption.
 *
 * error codes not yet defined, but will return 0 when successful
 */
int bef_deconstruct(int input, int output);

/* Memory-related boilerplate functions, crashes when out of memory */
void *bef_malloc(size_t sz);
void *bef_calloc(size_t nmemb, size_t sz);
void *bef_realloc(void *ptr, size_t sz);
void *bef_reallocarray(void *ptr, size_t nmemb, size_t sz);

#endif /* BEF_H */

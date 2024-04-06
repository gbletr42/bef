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
#define _FILE_OFFSET_BITS 64 //Make off_t 64 bits
#include "../config.h"
#include <stdint.h>
#include <stddef.h>
#include <sys/types.h>
#include <limits.h> //Apparently POSIX has SSIZE_MAX here

/* Our sexy magic number ( ͡° ͜ʖ ͡°) */
static const char *bef_magic = "BEFBABE";

/* Verbosity Flag */
extern uint8_t bef_vflag;

/* Raw Flag */
extern uint8_t bef_rflag;

/* Minimize Flag */
extern uint8_t bef_mflag;

/* Number of threads to use */
extern uint16_t bef_numT;

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
#define BEF_ERR_CM256		1454 //Error in CM256CC library
#define BEF_ERR_OPENFEC		1455 //Error in OpenFEC library
#define BEF_ERR_LEOPARD		1456 //Error in Leopard library
#define BEF_ERR_WIREHAIR	1457 //Error in Wirehair library


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

/* Default number of blocks to interleave is 5, which with default block size
 * and parities, provides protections for 20KiB burst corruption in the best
 * case and around 16KiB burst corruption in the worst case. I feel this is
 * pretty good burst corruption protection, and should serve to protect against
 * at least a bad sector or two in a 4096-byte sector hard disk.
 */
#define BEF_IL_N_DEFAULT 5

/* Max hash size in header in bytes */
#define BEF_HASH_SIZE 32

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
#define BEF_HASH_SHA512		10
#define BEF_HASH_BLAKE2B	11
#define BEF_HASH_CRC32C		12
#define BEF_HASH_DEFAULT	BEF_HASH_XXHASH

/* Our parity types, currently just copied liberasurecode
 * Haven't used/benchmarked non reed solomon codes */
//#define BEF_PAR_NONE	1 //No erasure code parities of any kind
//#define BEF_PAR_XOR	2 //Basic Flat XOR
#define BEF_PAR_J_V_RS	3 //Jerasure Vandermonde Reed Solomon
#define BEF_PAR_J_C_RS	4 //Jerasure Cauchy Reed Solomon
#define BEF_PAR_LE_V_RS	5 //liberasurecode Software Vandermonde Reed Solomon
#define BEF_PAR_I_V_RS	6 //Intel ISA-L Vandermonde Reed Solomon
#define BEF_PAR_I_C_RS	7 //Intel ISA-L Cauchy Reed Solomon
//#define BEF_PAR_SHSS	8 //NTT's SHSS erasure coding algorithm
//#define BEF_PAR_PHAZR	9 //Phazr.IO's erasure coding algorithm
#define BEF_PAR_F_V_RS	10 //zfec's libfec Software Vandermonde Reed Solomon
#define BEF_PAR_CM_C_RS	11 //cm256cc's Cauchy Reed Solomon
#define BEF_PAR_OF_V_RS	12 //OpenFEC's Vandermonde Reed Solomon
//#define BEF_PAR_OF_LDPC 13 //OpenFEC's LDPC Staircase
#define BEF_PAR_L_F_RS	14 //Chris Taylor's FFT Reed Solomon, Leopard
#define BEF_PAR_W_FC	15 //Chris Taylor's Fountain Code Wirehair

/* I find that generally my optimized version of zfec is pretty darn fast, and
 * it isn't an outside dependency.
 */
#define BEF_PAR_DEFAULT	BEF_PAR_F_V_RS

/* Special flags that modify the behavior of the format. Currently there is
 * support for up to 64 flags. This is to enable support for future features not
 * yet implemented.
 */
/* Nothing here yet! */

/* Custom types */
typedef uint8_t bef_hash_t;
typedef uint8_t bef_par_t;

/* Our real header, contains all necessary info. Padding is deliberately large
 * enough to allow for future additions to the format while keeping
 * backwards/forwards compatibility.
 */
struct bef_real_header {
	uint64_t	flags; //Special flags
	uint64_t	nbyte; //Total number of bytes in each fragment
	uint16_t	k; //Total number of data fragments per block
	uint16_t	m; //Total number of parity fragments per block
	uint16_t	il_n; //Number of blocks to interleave
	bef_par_t	par_t; //Parity type for all blocks
	bef_hash_t	hash_t; //Copy of bef_header's hash_t
	uint8_t		padding[40];
};

/* Our sexy header, total overhead is now forever 168 bytes */
struct bef_header {
	char			magic[7]; //Our magic number babe ^_^
	bef_hash_t		hash_t; //hash type for WHOLE FILE
	uint8_t			hash[BEF_HASH_SIZE]; //hash of header
	struct bef_real_header	header;
	struct bef_real_header	header_b; //backup header
};

/* Block Header struct, what follows after is the body of the block
 * Now twice the size from original at 80 bytes, twice the overhead.
 */
struct bef_frag_header {
	uint64_t	block_num; //block number, necessary for reconstruction
	uint64_t	pbyte; //Padded bytes for whole interleaved block
	uint8_t		h_hash[BEF_HASH_SIZE]; //hash of fragment header
	uint8_t		b_hash[BEF_HASH_SIZE]; //hash of fragment body
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
		   char **parity, size_t *frag_len, uint8_t flag,
		   struct bef_real_header header);

/* Frees the data structures allocated by bef_encode_ecc */
void bef_encode_free(char **data, char **parity, uint16_t k, uint16_t m);

/* Generalized erasure code decoding function. It takes in an array of
 * fragments, each fragment's size in byte, and outputs the decoded result to
 * the given output buffer. Like before, k and m need to be explicitly given.
 * Like the encode call, the output will be allocated by the function and it is
 * the caller's responsibility to free it with bef_decode_free().
 *
 * error codes not yet defined, but will return 0 when successful
 */
int bef_decode_ecc(char **frags, uint32_t frag_len, size_t frag_b,
		   char **output, size_t *onbyte, uint8_t flag,
		   struct bef_real_header header);

/* Frees the output buffer from bef_decode_ecc(). Of course you could also just
 * free() it yourself ;)
 */
void bef_decode_free(char *output);

/* Main Function that takes in a fileno and outputs in another given fileno the
 * formatted file. It is given a header containing necessary options as well as
 * a block size.
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
 * If il_n is set to 0, it will default to BEF_IL_N_DEFAULT
 *
 * If raw_f is NOT set to 0, it will write out a valid header to output,
 * otherwise it will just jump to generating the raw stream.
 *
 * error codes not yet defined, but will return 0 when successful
 */
int bef_construct(int input, int output, uint64_t bsize,
		  struct bef_real_header header);

/* Main function that does the inverse of the above. Takes in a given input and
 * output, as well as a header struct and the raw flag. If the raw flag is not
 * set to 0, it will use the values in the header struct, otherwise it'll ignore
 * them and read the header from the input.
 */
int bef_deconstruct(int input, int output, struct bef_real_header header);

/* Memory-related boilerplate functions, crashes when out of memory */
void *bef_malloc(size_t sz);
void *bef_calloc(size_t nmemb, size_t sz);
void *bef_realloc(void *ptr, size_t sz);
void *bef_reallocarray(void *ptr, size_t nmemb, size_t sz);

/* Get max number of fragments for a given parity type */
uint32_t bef_max_frag(bef_par_t par_t);

#endif /* BEF_H */

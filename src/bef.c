/* SPDX-License-Identifier: GPL-3.0-or-later */
/* bef (block erasure format) library code
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

//TODO: Add real error handling!

#include "bef.h"
#include "zfec.h"

#ifdef BEF_OPENSSL
#include <openssl/evp.h>
#endif
#ifdef BEF_BLAKE3
#include <blake3.h>
#endif
#ifdef BEF_ZLIB
#include <zlib.h>
#endif
#ifdef BEF_LIBERASURECODE
#include <erasurecode.h>
#endif

#include <string.h>
#include <xxhash.h>
#include <stdlib.h>
#include <assert.h>
#include <unistd.h>
#include <sys/random.h>
#include <endian.h>
#include <errno.h>

#define BEF_SAFE_READ	0
#define BEF_SAFE_WRITE	1

#define BEF_PIPE_BUF	65535 //One less than full pipe

/* Struct for libfec header */
struct bef_fec_header {
	uint32_t block_num;
	uint32_t padding;
};

void *bef_malloc(size_t sz)
{
	void *ptr = malloc(sz);
	assert(ptr != NULL);
	return ptr;
}

void *bef_calloc(size_t nmemb, size_t sz)
{
	void *ptr = calloc(nmemb, sz);
	assert(ptr != NULL);
	return ptr;
}

void *bef_realloc(void *ptr, size_t sz)
{
	assert(ptr != NULL);
	ptr = realloc(ptr, sz);
	assert(ptr != NULL);
	return ptr;
}

void *bef_reallocarray(void *ptr, size_t nmemb, size_t sz)
{
	assert(ptr != NULL);
	ptr = reallocarray(ptr, nmemb, sz);
	assert(ptr != NULL);
	return ptr;
}

/* Our great padding function from the sky, integrating all the messy padding
 * problems I was having. This function integrates the 4 layers of padding
 * previously divided up into 1 great padding function, which pads it to il_n
 * (bsize + (k - bsize % k)) bytes. For those who are curious, this is what this
 * function was unifying (may God forgive me for this evil I am about to type)
 *
 * 1. First we must pad out at least il_n - bytes bytes, if bytes < il_n.
 * 2. Second we must pad out at least k - bytes per interleaved block, if its
 * less than k bytes.
 * 3. Third we must pad out at least byte % k bytes to all but the last
 * fragment, if byte % k != 0, to ensure equal sized fragments for libfec (and
 * future low level backends).
 * 4. Fourth we must pad out the resulting fragment length to nbyte, if fragment
 * length < nbyte.
 *
 * Each one of these would have to be placed in different structs, meaning that
 * without unification, the underlying data would look like this mess
 * struct -> struct -> struct -> struct -> data -> padding -> struct -> data -> padding -> [...]
 *
 * Simply evil and Satanic, the diagram doesn't even fit on 80 characters!
 * We can do better without sacrificing any of the protective properties of our
 * format with this padding function from the sky.
 *
 * This also has the added benefit of there being one great padding at the end,
 * removing the need for per-fragment padding. However, we don't know how much
 * is here until we get there, so it'll have to stay even though we only need
 * one :(. The horrors of a format that cannot be seekable by design,
 * 8*(k+m)*il_n - 8 wasted bytes.
 *
 * inbyte must obviously be at most il_n * (bsize + (k - bsize % k)), and input
 * must be as large as inbyte.
 *
 * returns the number of total padded bytes
 */
static uint64_t bef_sky_padding(char *input, size_t inbyte,
				uint16_t il_n, uint16_t k, uint64_t bsize)
{
	uint64_t pbyte = il_n * (bsize + (k - bsize % k));

	if(inbyte < pbyte) {
		pbyte -= inbyte;
		memset(input + inbyte, '\0', pbyte);
	} else
		pbyte = 0;

	return pbyte;
}


ssize_t bef_safe_rw(int fd, void *buf, size_t nbyte, uint8_t flag)
{
	ssize_t ret = 1; //Set to > 0 for loop
	size_t inbyte;
	size_t offset = 0;

	if(nbyte > BEF_PIPE_BUF &&
	   (fd == STDIN_FILENO || fd == STDOUT_FILENO || fd == STDERR_FILENO))
		inbyte = BEF_PIPE_BUF;
	else
		inbyte = nbyte;

	/* Keep trying if interrupted or told to try again, or if buffer is not
	 * full
	 */
	while((ret == -1 && (errno == EAGAIN || errno == EINTR)) ||
	      (offset != nbyte && ret > 0)) {
		if(flag == BEF_SAFE_READ)
			ret = read(fd, buf + offset, inbyte);
		else
			ret = write(fd, buf + offset, inbyte);

		if(ret > 0) {
			offset += (size_t) ret;
			if(nbyte - offset < inbyte)
				inbyte = nbyte - offset;
		}
	}

	if(ret == -1)
		offset = -1; //If erred with -1, it'll still return -1

	return offset;
}

/* Both header and frag headers MUST BE LITTLE ENDIAN!!!!! */
static void bef_prepare_header(struct bef_real_header *header)
{
	header->flags = htole64(header->flags);
	header->k = htole16(header->k);
	header->m = htole16(header->m);
	header->nbyte = htole64(header->nbyte);
	header->il_n = htole16(header->il_n);
}

static void bef_prepare_frag_header(struct bef_frag_header *header)
{
	header->pbyte = htole64(header->pbyte);
}

static void bef_unprepare_header(struct bef_real_header *header)
{
	header->flags = le64toh(header->flags);
	header->k = le16toh(header->k);
	header->m = le16toh(header->m);
	header->nbyte = le64toh(header->nbyte);
	header->il_n = le16toh(header->il_n);
}

static void bef_unprepare_frag_header(struct bef_frag_header *header)
{
	header->pbyte = le64toh(header->pbyte);
}

#ifdef BEF_ZLIB
static int bef_digest_crc32(const char *input, size_t nbyte, uint8_t *output)
{
	uLong crc = crc32(0L, Z_NULL, 0);
	crc = crc32(crc, (const Bytef *) input, (uInt) nbyte);

	/* Check sizes and convert endianness */
	if(sizeof(crc) == sizeof(uint32_t))
		crc = (uLong) htole32((uint32_t) crc);
	else if (sizeof(crc) == sizeof(uint64_t))
		crc = (uLong) htole64((uint64_t) crc);
	else
		return -BEF_ERR_INVALSIZE;

	memcpy(output, &crc, sizeof(crc)); //depends on platforms, 4 or 8 bytes
	return 0;
}
#endif

#ifdef BEF_BLAKE3
static int bef_digest_blake3(const char *input, size_t nbyte, uint8_t *output)
{
	blake3_hasher context;
	blake3_hasher_init(&context);
	blake3_hasher_update(&context, input, nbyte);
	blake3_hasher_finalize(&context, output, BEF_HASH_SIZE);
	return 0;
}
#endif

#ifdef BEF_OPENSSL
static int bef_digest_openssl(const char *input, uint8_t *output, size_t nbyte,
			      const EVP_MD *(*f_evp)(void))
{
	int ret = 0;
	EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
	unsigned int digest_len;
	unsigned char digest[BEF_HASH_SIZE];

	if(mdctx == NULL) {
		ret = -BEF_ERR_NULLPTR;
		goto out;
	}

	ret = EVP_DigestInit_ex(mdctx, (*f_evp)(), NULL);
	if(ret != 1) {
		ret = -BEF_ERR_OPENSSL;
		goto out;
	}

	ret = EVP_DigestUpdate(mdctx, (const unsigned char *) input, nbyte);
	if(ret != 1) {
		ret = -BEF_ERR_OPENSSL;
		goto out;
	}

	ret = EVP_DigestFinal_ex(mdctx, digest, &digest_len);
	if(ret != 1) {
		ret = -BEF_ERR_OPENSSL;
		goto out;
	}

	if(digest_len > BEF_HASH_SIZE)
		digest_len = BEF_HASH_SIZE; //Truncate to hash size
	memcpy(output, digest, (size_t) digest_len);

	if(ret != 0)
		ret = 0;

out:
	EVP_MD_CTX_free(mdctx);
	return ret;
}
#endif

/* We use XXH3_128bits() as it's fastest and *good enough*
 * For cryptographic purposes, recommendation is to use BLAKE3 instead
 */
static int bef_digest_xxhash(const char *input, size_t nbyte, uint8_t *output)
{
	XXH128_hash_t hash = XXH3_128bits(input, nbyte);
	XXH128_canonical_t canon; //canonical big endian representation
	XXH128_canonicalFromHash(&canon, hash);
	memcpy(output, &hash, sizeof(canon));
	return 0;
}

//output MUST and is assumed to be BEF_HASH_SIZE members (256 bits/32 bytes)
int bef_digest(const char *input, size_t nbyte, uint8_t *output,
	       bef_hash_t hash_t)
{
	int ret = 0;
#ifdef BEF_OPENSSL
	const EVP_MD *(*f_evp)(void) = NULL; //for OpenSSL
#endif

	/* Ensure the output is clean first */
	memset(output, '\0', BEF_HASH_SIZE);

	switch(hash_t) {
	case BEF_HASH_NONE:
		break;
#ifdef BEF_OPENSSL
	case BEF_HASH_SHA1:
		f_evp = &EVP_sha1;
		ret = bef_digest_openssl(input, output, nbyte, f_evp);
		break;
	case BEF_HASH_SHA256:
		f_evp = &EVP_sha256;
		ret = bef_digest_openssl(input, output, nbyte, f_evp);
		break;
	case BEF_HASH_SHA3:
		f_evp = &EVP_sha3_256;
		ret = bef_digest_openssl(input, output, nbyte, f_evp);
		break;
	case BEF_HASH_BLAKE2S:
		f_evp = &EVP_blake2s256;
		ret = bef_digest_openssl(input, output, nbyte, f_evp);
		break;
	case BEF_HASH_MD5:
		f_evp = &EVP_md5;
		ret = bef_digest_openssl(input, output, nbyte, f_evp);
		break;
#endif
#ifdef BEF_BLAKE3
	case BEF_HASH_BLAKE3:
		ret = bef_digest_blake3(input, nbyte, output);
		break;
#endif
#ifdef BEF_ZLIB
	case BEF_HASH_CRC32:
		ret = bef_digest_crc32(input, nbyte, output);
		break;
#endif
	case BEF_HASH_XXHASH:
		ret = bef_digest_xxhash(input, nbyte, output);
		break;
	default:
		ret = -BEF_ERR_INVALINPUT;
		break;
	}

	return ret;
}

#ifdef BEF_LIBERASURECODE
static ec_backend_id_t bef_liberasurecode_par_switch(bef_par_t par_t)
{
	ec_backend_id_t ret;

	switch(par_t) {
	case BEF_PAR_J_V_RS:
		ret = EC_BACKEND_JERASURE_RS_VAND;
		break;
	case BEF_PAR_J_C_RS:
		ret = EC_BACKEND_JERASURE_RS_CAUCHY;
		break;
	case BEF_PAR_LE_V_RS:
		ret = EC_BACKEND_LIBERASURECODE_RS_VAND;
		break;
	case BEF_PAR_I_V_RS:
		ret = EC_BACKEND_ISA_L_RS_VAND;
		break;
	case BEF_PAR_I_C_RS:
		ret = EC_BACKEND_ISA_L_RS_CAUCHY;
		break;
	default:
		ret = EC_BACKENDS_MAX;
		break;
	}

	return ret;
}

static int bef_encode_liberasurecode(const char *input, size_t inbyte,
				     char **data, char **parity,
				     size_t *frag_len, int k, int m,
				     bef_par_t par_t)
{
	int ret;
	int desc;
	ec_backend_id_t backend_id;
	struct ec_args args = {0};
	char **tmp_data;
	char **tmp_parity;
	args.k = k;
	args.m = args.hd = m; //Only support RS for now

	backend_id = bef_liberasurecode_par_switch(par_t);
	if(backend_id == EC_BACKENDS_MAX) {
		ret = -BEF_ERR_INVALINPUT;
		goto out;
	}

	desc = liberasurecode_instance_create(backend_id, &args);
	if(desc < 0) {
		ret = -desc;
		goto out;
	}

	ret = liberasurecode_encode(desc, input, inbyte, &tmp_data, &tmp_parity,
				    (uint64_t *) frag_len);
	if(ret < 0) {
		ret = -ret;
		goto instance_cleanup;
	}

	/* Copy over the results */
	for(int i = 0; i < k; i++) {
		*(data + i) = bef_malloc(*frag_len);
		memcpy(*(data + i), *(tmp_data + i), *frag_len);
	}
	for(int i = 0; i < m; i++) {
		*(parity + i) = bef_malloc(*frag_len);
		memcpy(*(parity + i), *(tmp_parity + i), *frag_len);
	}

	/* Free our given buffers */
	ret = liberasurecode_encode_cleanup(desc, tmp_data, tmp_parity);
	if(ret < 0) {
		ret = -ret;
		bef_encode_free(data, parity, k, m);
	}

instance_cleanup:
	liberasurecode_instance_destroy(desc); //DOES NOT CHECK FOR ERRORS!
out:
	return ret;
}
#endif

/* Due to this being low level, we'll have to add some pivotal metadata
 * ourselves as a header. First of all, the block number of the block, and since
 * we know how many k there are, that's all we need to know regarding whether
 * it's a primary or secondary block.
 */
static int bef_encode_libfec(const char *input, size_t inbyte, char **data,
			     char **parity, size_t *frag_len, int k, int m)
{
	struct bef_fec_header header;
	size_t size = inbyte / k; //Size of each data fragment, prepadded
	unsigned int block_nums[m];
	fec_t *context;
	*frag_len = sizeof(header) + size;

	/* Allocate our arrays, moving the pointer past the header. I know, it's
	 * a bit hacky, but it works!
	 */
	for(int i = 0; i < k; i++) {
		*(data + i) = malloc(size + sizeof(header));
		header.block_num = i;

		memcpy(*(data + i), &header, sizeof(header));
		memcpy(*(data + i) + sizeof(header), input + i * size, size);

		*(data + i) += sizeof(header); //Evil and Satanic
	}
	for(int i = 0; i < m; i++) {
		*(parity + i) = malloc(size + sizeof(header));
		block_nums[i] = k + i;
		header.block_num = k + i;
		memcpy(*(parity + i), &header, sizeof(header));
		*(parity + i) += sizeof(header); //Evil and Satanic
	}

	/* API says "at least once", so surely multiple times won't hurt? */
	fec_init();

	context = fec_new(k, k+m);

	/* I rather live with the warning than add a million consts */
	fec_encode(context, (unsigned char **)data, (unsigned char **) parity,
		   block_nums, m, size);

	/* Now set the pointers back */
	for(int i = 0; i < k; i++)
		*(data + i) -= sizeof(header);
	for(int i = 0; i < m; i++)
		*(parity + i) -= sizeof(header);

	fec_free(context);
	return 0;
}

int bef_encode_ecc(const char *input, size_t inbyte, char **data,
		   char **parity,  size_t *frag_len, int k, int m,
		   bef_par_t par_t)
{
	int ret = 0;

	switch(par_t) {
#ifdef BEF_LIBERASURECODE
	case BEF_PAR_J_V_RS:
	case BEF_PAR_J_C_RS:
	case BEF_PAR_LE_V_RS:
	case BEF_PAR_I_V_RS:
	case BEF_PAR_I_C_RS:
		ret = bef_encode_liberasurecode(input, inbyte, data, parity,
						frag_len, k, m, par_t);
		break;
#endif
	case BEF_PAR_F_V_RS:
		ret = bef_encode_libfec(input, inbyte, data, parity, frag_len,
					k, m);
		break;
	default:
		ret = -BEF_ERR_INVALINPUT;
		break;
	}

	return ret;
}

void bef_encode_free(char **data, char **parity, int k, int m)
{
	for(int i = 0; i < k; i++)
		free(*(data + i));
	for(int i = 0; i < m; i++)
		free(*(parity + i));
}

#ifdef BEF_LIBERASURECODE
static int bef_decode_liberasurecode(char **frags, uint16_t frag_len,
				     size_t frag_b, char **output,
				     size_t *onbyte, int k, int m,
				     bef_par_t par_t)
{
	int ret;
	int desc;
	ec_backend_id_t backend_id;
	struct ec_args args = {0};
	char *tmp_output;
	uint64_t tmp_len;
	args.k = k;
	args.m = args.hd = m;

	backend_id = bef_liberasurecode_par_switch(par_t);
	if(backend_id == EC_BACKENDS_MAX) {
		ret = -BEF_ERR_INVALINPUT;
		goto out;
	}

	ret = liberasurecode_backend_available(backend_id);
	if(ret < 0) {
		ret = -ret;
		goto out;
	}

	desc = liberasurecode_instance_create(backend_id, &args);
	if(desc < 0) {
		ret = -desc;
		goto out;
	}

	ret = liberasurecode_decode(desc, frags, (int) frag_len,
				    (uint64_t) frag_b, 0, &tmp_output,
				    &tmp_len);
	if(ret < 0) {
		ret = -ret;
		goto instance_cleanup;
	}

	/* Copy over our data */
	*output = bef_malloc((size_t) tmp_len);
	*onbyte = tmp_len;
	memcpy(*output, tmp_output, *onbyte);

	/* free the liberasurecode structures */
	ret = liberasurecode_decode_cleanup(desc, tmp_output);
	if(ret < 0) {
		ret = -ret;
		bef_decode_free(*output);
	} else if(ret > 0)
		ret = 0;

instance_cleanup:
	liberasurecode_instance_destroy(desc); //DOES NOT CHECK FOR ERRORS!!!
out:
	return ret;
}
#endif

/* By default, our program automatically grabs the 'primary' blocks in
 * linear format, which means we only need to find out which ones aren't what
 * they say they are.
 */
static int bef_decode_libfec(char **frags, uint16_t frag_len, size_t frag_b,
			     char **output, size_t *onbyte, int k, int m)
{
	fec_t *context;
	char *out_arr[m]; //At most m outputs
	unsigned int block_nums[frag_len];
	uint8_t found = 0;
	struct bef_fec_header header;
	size_t size = frag_b - sizeof(header);
	char *tmp; //To avoid duplicate paths later
	*onbyte = size * k;

	/* See the odd one out and allocate an output */
	for(uint16_t i = 0; i < frag_len; i++) {
		memcpy(&header, *(frags+i), sizeof(header));
		if(header.block_num != i)
			out_arr[found++] = malloc(size);
		block_nums[i] = header.block_num;

		/* Do our evil pointer arithmetic hackery again */
		*(frags + i) += sizeof(header);
	}

	/* Allocate our output buffer */
	*output = malloc(*onbyte);

	if(found > 0) { //We can just read directly if they're all good
		fec_init(); //Same question as before, guess we'll find out

		context = fec_new(k, k+m);

		fec_decode(context, (unsigned char **) frags,
			   (unsigned char **) out_arr, block_nums, size);

		fec_free(context); //Freed here rather than at return
	}

	/* Write to output buffer */
	found = 0;
	for(uint16_t i = 0; i < frag_len; i++) {
		if(block_nums[i] == i)
			tmp = *(frags + i);
		else
			tmp = out_arr[found++];

		memcpy(*output + i * size, tmp, size);
	}

	/* Undo our pointer hackery */
	for(uint16_t i = 0; i < frag_len; i++)
		*(frags + i) -= sizeof(header);

	for(uint8_t i = 0; i < found; i++)
		free(out_arr[i]);
	return 0;
}

int bef_decode_ecc(char **frags, uint16_t frag_len, size_t frag_b,
		   char **output, size_t *onbyte, int k, int m, bef_par_t par_t)
{
	int ret = 0;

	/* Not enough fragments */
	if(frag_len < k)
		return -BEF_ERR_NEEDMORE;
	else if(frag_len == 0)
		return -BEF_ERR_INVALINPUT;

	/* All our codes require at least one parity, including BEF_PAR_NONE */
	if(m == 0)
		return -BEF_ERR_INVALINPUT;

	switch(par_t) {
#ifdef BEF_LIBERASURECODE
	case BEF_PAR_J_V_RS:
	case BEF_PAR_J_C_RS:
	case BEF_PAR_LE_V_RS:
	case BEF_PAR_I_V_RS:
	case BEF_PAR_I_C_RS:
		ret = bef_decode_liberasurecode(frags, frag_len, frag_b, output,
						onbyte, k, m, par_t);
		break;
#endif
	case BEF_PAR_F_V_RS:
		ret = bef_decode_libfec(frags, frag_len, frag_b, output, onbyte,
					k, m);
		break;
	default:
		ret = -BEF_ERR_INVALINPUT;
		break;
	}

	return ret;
}

void bef_decode_free(char *output)
{
	free(output);
}

static int bef_construct_header(int input, char *ibuf, size_t ibuf_s,
				uint64_t bsize, size_t *lret,
				struct bef_header *header)
{
	int ret;
	ssize_t rret;
	uint16_t k = header->header.k;
	uint16_t m = header->header.m;
	char **data = bef_malloc(k * sizeof(*data));
	char **parity = bef_malloc(m * sizeof(*parity));
	size_t frag_len;

	/* Our lovely, sexy, beautiful magic number */
	memcpy(header->magic, bef_magic, 7);
	header->hash_t = header->header.hash_t;

	/* To get nbyte, which depends on the backend used, we are going to
	 * construct the first block twice (so I don't have to lug around a
	 * evil output buffer or worse, two char **s). I know, I know! It's evil
	 * and wrong, but unless you want like 4 fragments in total, it'll be
	 * fine!
	 */
	rret = bef_safe_rw(input, ibuf, ibuf_s, BEF_SAFE_READ);
	if(rret == -1 || rret == 0) {
		ret = -BEF_ERR_READERR;
		goto out;
	}

	/* Pad out if necessary */
	bef_sky_padding(ibuf, (size_t) rret, header->header.il_n,
			header->header.k, bsize);

	*lret = (size_t) rret;

	if(rret != ibuf_s / header->header.il_n)
		rret = ibuf_s / header->header.il_n; //Set to size of one block

	ret = bef_encode_ecc(ibuf, rret, data, parity, &frag_len,
			     k, m, header->header.par_t);
	if(ret != 0)
		goto out;

	header->header.nbyte = (uint64_t) (frag_len + sizeof(struct bef_frag_header));

	/* Let prepare our header, converting everything to Little Endian */
	bef_prepare_header(&(header->header));

	/* let's now compute our hash! */
	ret = bef_digest((char *) &(header->header), sizeof(header->header),
			 header->hash, header->hash_t);

	/* Let's now make our backup header, in case freaky things happen */
	memcpy(&(header->header_b), &(header->header), sizeof(header->header));

	/* And that's all folks! */

	bef_encode_free(data, parity, k, m);
out:
	free(data);
	free(parity);
	return ret;
}

static int bef_construct_frag(char *output, char *body, size_t frag_len,
			      bef_hash_t hash_t, uint64_t pbyte)
{
	int ret;
	struct bef_frag_header header;
	size_t offset = 0;

	header.pbyte = pbyte;

	/* hash not set yet */
	memset(header.hash, '\0', sizeof(header.hash));

	bef_prepare_frag_header(&header);
	memcpy(output, &header, sizeof(header));
	offset += sizeof(header);
	memcpy(output + offset, body, frag_len);

	/* Set hash */
	ret = bef_digest(output, sizeof(header) + frag_len, header.hash,
			 hash_t);
	if(ret != 0)
		return ret;
	memcpy(output, &header, sizeof(header));

	return 0;
}

/* output MUST BE AT LEAST (k+m) * nbyte large,
 * also frag_len + sizeof(bef_header) MUST EQUAL nbyte!!!
 */
static int bef_construct_blocks(char *output, char ***blocks,
				size_t frag_len, uint64_t pbyte,
				struct bef_real_header header)
{
	int ret;
	size_t offset = 0;

	for(uint16_t i = 0; i < header.k + header.m; i++) {
		for(uint16_t j = 0; j < header.il_n; j++) {
			ret = bef_construct_frag(output + offset, blocks[j][i],
						 frag_len, header.hash_t,
						 pbyte);
			if(ret != 0)
				return ret;
			offset += (size_t) header.nbyte;
		}
	}

	return 0;
}

static void bef_construct_buffers(char ****blocks, uint16_t km, uint16_t il_n)
{
	*blocks = bef_malloc(il_n * sizeof(*(*blocks)));
	for(uint16_t i = 0; i < il_n; i++)
		*(*blocks + i) = bef_malloc(km * sizeof(*(*(*blocks))));
}

static void bef_construct_free(char ***blocks, uint16_t il_n)
{
	for(uint16_t i = 0; i < il_n; i++)
		free(*(blocks + i));
	free(blocks);
}

static int bef_encode_blocks(char *ibuf, size_t ibuf_s, char *obuf,
			     uint64_t bsize, struct bef_real_header header)
{
	int ret;
	char ***blocks;
	char **frags;
	size_t frag_len = 0;
	uint64_t pbyte = bef_sky_padding(ibuf, ibuf_s, header.il_n, header.k,
					 bsize);
	size_t fbyte = (ibuf_s + pbyte) / header.il_n;

	bef_construct_buffers(&blocks, header.k + header.m, header.il_n);

	for(uint16_t i = 0; i < header.il_n; i++) {
		frags = *(blocks + i);

		ret = bef_encode_ecc(ibuf + i * fbyte, fbyte, frags,
				     frags + header.k, &frag_len, header.k,
				     header.m, header.par_t);

		/* Free our older arrays, if this isn't the first one */
		if(ret != 0 && i > 0) {
			for(uint16_t j = i; j > 0; j--)
				bef_encode_free(*(blocks + j - 1),
						*(blocks + j - 1) + header.k,
						header.k, header.m);
		}

		if(ret != 0)
			goto out;
	}

	ret = bef_construct_blocks(obuf, blocks, frag_len, pbyte, header);

	for(uint16_t i = 0; i < header.il_n; i++)
		bef_encode_free(*(blocks + i), *(blocks + i) + header.k,
				header.k, header.m);
out:
	bef_construct_free(blocks, header.il_n);
	return ret;
}

static int bef_construct_encode(int input, int output,
				char *ibuf, uint64_t bsize, size_t lret,
				struct bef_real_header header)
{
	int ret;
	ssize_t bret;
	size_t obuf_s = (header.k + header.m) * header.nbyte * header.il_n;
	char *obuf = bef_malloc(obuf_s);
	size_t ibuf_s = header.il_n * (bsize + (header.k - bsize % header.k));

	/* Redo very first few blocks, source still in input */
	ret = bef_encode_blocks(ibuf, lret, obuf, bsize, header);
	if(ret != 0)
		goto out;

	bret = bef_safe_rw(output, obuf, obuf_s, BEF_SAFE_WRITE);
	if(bret != obuf_s) {
		ret = -BEF_ERR_WRITEERR;
		goto out;
	}

	/* Eternal read loop incoming */
	while(1) {
		bret = bef_safe_rw(input, ibuf, ibuf_s, BEF_SAFE_READ);
		if(bret == 0)
			break; //No more data to read!
		else if(bret == -1) {
			ret = -BEF_ERR_READERR;
			goto out;
		}

		ret = bef_encode_blocks(ibuf, bret, obuf, bsize, header);
		if(ret != 0)
			goto out;

		bret = bef_safe_rw(output, obuf, obuf_s, BEF_SAFE_WRITE);
		if(bret != obuf_s) {
			ret = -BEF_ERR_WRITEERR;
			goto out;
		}
	}

out:
	free(obuf);
	free(ibuf);
	return ret;
}

/* Our lovely file constructor! Split in two parts ^_^ */
int bef_construct(int input, int output, uint64_t bsize,
		  struct bef_real_header header, uint8_t raw_f)
{
	int ret;
	ssize_t bret;
	char *ibuf;
	size_t ibuf_s;
	struct bef_header head;
	size_t lret;

	if(bsize == 0)
		bsize = BEF_BSIZE;
	if(header.par_t == 0)
		header.par_t = BEF_PAR_DEFAULT;
	if(header.hash_t == 0)
		header.hash_t = BEF_HASH_DEFAULT;
	if(header.k == 0)
		header.k = BEF_K_DEFAULT;
	if(header.m == 0)
		header.m = BEF_M_DEFAULT;
	if(header.il_n == 0)
		header.il_n = BEF_IL_N_DEFAULT;

	/* Estimate size of our shared input buffer, using bsize and k */
	ibuf_s = header.il_n * (bsize + (header.k - bsize % header.k));
	ibuf = bef_malloc(ibuf_s);

	head.header = header;

	if(raw_f == 0) {
		ret = bef_construct_header(input, ibuf, ibuf_s, bsize, &lret,
					   &head);
		if(ret != 0)
			return ret;

		/* Write our header to output */
		bret = write(output, &head, sizeof(head));
		if(bret != sizeof(head))
			return -BEF_ERR_WRITEERR;
	} else {
		bret = bef_safe_rw(input, ibuf, ibuf_s, BEF_SAFE_READ);
		if(bret == -1)
			return -BEF_ERR_READERR;
		lret = (size_t) bret;
	}

	if(head.header.nbyte == 0)
		return -BEF_ERR_INVALINPUT;

	/* ibuf should be freed by this function, so no need to check */
	ret = bef_construct_encode(input, output, ibuf, bsize, lret,
				   head.header);
	if(ret != 0)
		return ret;

	return ret;
}

static int bef_verify_fragment(char *frag, uint64_t nbyte, bef_hash_t hash_t)
{
	int ret;
	uint8_t hash[BEF_HASH_SIZE];
	struct bef_frag_header header;

	/* Copy over our header */
	memcpy(&header, frag, sizeof(header));

	/* Zero out the original hash */
	memset(frag + sizeof(header) - sizeof(header.hash),
	       '\0', sizeof(header.hash));

	/* Get our hash */
	ret = bef_digest(frag, nbyte, hash, hash_t);
	if(ret != 0)
		return ret;

	/* Compare our two hashes */
	if(memcmp(header.hash, hash, sizeof(hash)) != 0) {
		return -BEF_ERR_INVALHASH;
	} else
		return 0;
}

static void bef_deconstruct_buffers(char ***buf_arr, uint16_t km,
				    uint64_t nbyte)
{
	*buf_arr = bef_malloc(km * sizeof(*(*buf_arr)));
	for(uint16_t i = 0; i < km; i++)
		*(*buf_arr + i) = bef_malloc(nbyte);
}

static void bef_deconstruct_free(char **buf_arr, uint16_t km)
{
	for(uint16_t i = 0; i < km; i++)
		free(*(buf_arr + i));
	free(buf_arr);
}

static int bef_deconstruct_header(int input, struct bef_real_header *header)
{
	int ret;
	ssize_t bret;
	struct bef_header head;
	uint8_t hash[BEF_HASH_SIZE];

	bret = read(input, &head, sizeof(head));
	if(bret != sizeof(head))
		return -BEF_ERR_READERR;

	if(memcmp(head.magic, bef_magic, 7) != 0)
		return -BEF_ERR_INVALHEAD; //WTF, it's not our BABE!?
	ret = bef_digest((char *) &(head.header), sizeof(head.header), hash,
			 head.hash_t);
	if(ret != 0)
		return ret;

	if(memcmp(hash, head.hash, BEF_HASH_SIZE) != 0) {
		/* Oh noes! Hopefully our backup is okay... */
		ret = bef_digest((char *) &(head.header_b),
				 sizeof(head.header_b), hash, head.hash_t);
		if(ret != 0)
			return ret;
		if(memcmp(hash, head.hash, BEF_HASH_SIZE) != 0) {
			return -BEF_ERR_INVALHEAD; //How sad!
		} else
			*header = head.header_b;
	} else
		*header = head.header;

	bef_unprepare_header(header); //Gotta get right endianness

	return 0;
}

static int bef_get_parity(char *ibuf, char *obuf,
			  uint32_t block_num, uint16_t m,
			  struct bef_real_header header)
{
	int ret = -BEF_ERR_INVALHASH; //We are already at a invalid hash
	uint64_t frag_b = header.nbyte - sizeof(struct bef_frag_header);
	size_t index;

	for(; ret == -BEF_ERR_INVALHASH; m++) {
		if(m >= header.m)
			return -BEF_ERR_NEEDMORE;

		index = (header.k + m) * header.il_n + block_num;
		index *= header.nbyte;

		ret = bef_verify_fragment(ibuf + index, header.nbyte,
					  header.hash_t);
	}

	if(ret != 0)
		return ret;
	else {
		memcpy(obuf, ibuf + index + sizeof(struct bef_frag_header),
		       frag_b);
		return 0;
	}
}

static int bef_deconstruct_block(char *ibuf, char **obuf, size_t *obuf_s,
				 uint64_t *pbyte, uint32_t block_num,
				 struct bef_real_header header)
{
	int ret;
	char *output;
	size_t onbyte;
	char **buf_arr;
	struct bef_frag_header frag_h;
	uint64_t frag_b = header.nbyte - sizeof(frag_h);
	uint16_t m = 0;
	uint64_t index = 0;

	bef_deconstruct_buffers(&buf_arr, header.k + header.m, frag_b);

	for(uint16_t i = 0; i < header.k; i++) {
		index = (i * header.il_n + block_num) * header.nbyte;

		/* Get our fragment header */
		memcpy(&frag_h, ibuf + index, sizeof(frag_h));
		bef_unprepare_frag_header(&frag_h);

		ret = bef_verify_fragment(ibuf + index, header.nbyte,
					  header.hash_t);
		if(ret == -BEF_ERR_INVALHASH) { //Gotta get parity
			ret = bef_get_parity(ibuf, *(buf_arr + i),
					     block_num, m++, header);
			if(ret != 0)
				goto out;
		} else if(ret != 0) {
				goto out;
		} else {
			/* Set pbyte if found */
			if(frag_h.pbyte > 0 && *pbyte == 0)
				*pbyte = frag_h.pbyte;
			memcpy(*(buf_arr + i), ibuf + index + sizeof(frag_h),
			       frag_b);
		}
	}

	/* And now after that digusting loop */
	ret = bef_decode_ecc(buf_arr, header.k, frag_b, &output,
			     &onbyte, header.k, header.m, header.par_t);
	if(ret != 0)
		goto out;

	/* Allocate our output buffer, if not already allocated */
	if(*obuf_s == 0) {
		*obuf_s = header.il_n * onbyte;
		*obuf = bef_malloc(*obuf_s);
	}

	/* Copy over the results to real output buffer */
	memcpy(*obuf + block_num * onbyte,
	       output, onbyte);

	bef_decode_free(output);
out:
	bef_deconstruct_free(buf_arr, header.k + header.m);
	return ret;
}

/* Surprisingly simpler than encoding, but still takes up a far too many lines
 * of code
 */
int bef_deconstruct(int input, int output, struct bef_real_header header,
		    uint8_t raw_f)
{
	int ret = 0;
	ssize_t bret;
	char *ibuf = NULL;
	char *obuf = NULL;
	size_t ibuf_s;
	size_t obuf_s = 0; //Not known yet
	uint64_t pbyte = 0;

	if(raw_f == 0) {
		/* Get our header and verify its sanity */
		ret = bef_deconstruct_header(input, &header);
		if(ret != 0)
			goto out;

		if(header.k == 0)
			return -BEF_ERR_INVALINPUT;
		if(header.nbyte == 0)
			return -BEF_ERR_INVALINPUT;
		if(header.il_n == 0)
			return -BEF_ERR_INVALINPUT;
		if(header.m == 0)
			return -BEF_ERR_INVALINPUT;
		if(header.par_t == 0)
			return -BEF_ERR_INVALINPUT;
		if(header.hash_t == 0)
			return -BEF_ERR_INVALINPUT;
	} else {
		if(header.k == 0)
			header.k = BEF_K_DEFAULT;
		if(header.m == 0)
			header.m = BEF_M_DEFAULT;
		if(header.il_n == 0)
			header.il_n = BEF_IL_N_DEFAULT;
		if(header.par_t == 0)
			header.par_t = BEF_PAR_DEFAULT;
		if(header.hash_t == 0)
			header.hash_t = BEF_HASH_DEFAULT;
	}

	/* Allocate our buffers */
	ibuf_s = (header.k + header.m) * header.nbyte * header.il_n;
	ibuf = bef_malloc(ibuf_s);

	/* Another eternal read loop incoming */
	while(1) {
		bret = bef_safe_rw(input, ibuf, ibuf_s, BEF_SAFE_READ);
		if(bret == 0) {
			break; //Read it all folks!
		} else if(bret == -1) {
			ret = -BEF_ERR_READERR;
			goto out;
		}

		for(uint16_t block = 0; block < header.il_n; block++) {
			ret = bef_deconstruct_block(ibuf, &obuf, &obuf_s,
						    &pbyte, block, header);
			if(ret != 0)
				goto out;
		}

		/* Check for integer overflow */
		if(obuf_s - pbyte > obuf_s){//Impossible, unless overflowed
			ret = -BEF_ERR_OVERFLOW;
			goto out;
		}

		bret = bef_safe_rw(output, obuf, obuf_s - pbyte,
				   BEF_SAFE_WRITE);
		if(bret != obuf_s - pbyte) {
			ret = -BEF_ERR_WRITEERR;
			goto out;
		}
	}

out:
	free(obuf);
	free(ibuf);
	return ret;
}

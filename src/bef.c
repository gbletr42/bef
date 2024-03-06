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
#include "fec.h"

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

/* Global dynamic lookup array representing the location of m parities */
static uint64_t *m_arr = NULL;

/* Struct for libfec header */
struct bef_fec_header {
	uint32_t block_num;
	uint32_t pbyte;
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

/* Both header and frag headers MUST BE LITTLE ENDIAN!!!!! */
static void bef_prepare_header(struct bef_header *header)
{
	header->header.seed = htole32(header->header.seed);
	header->header.nblock = htole32(header->header.nblock);
	header->header.k = htole16(header->header.k);
	header->header.m = htole16(header->header.m);
	header->header.nbyte = htole64(header->header.nbyte);
}

static void bef_prepare_frag_header(struct bef_frag_header *header)
{
	header->block_num = htole32(header->block_num);
	header->frag_num = htole16(header->frag_num);
}

static void bef_unprepare_header(struct bef_header *header)
{
	header->header.seed = le32toh(header->header.seed);
	header->header.nblock = le32toh(header->header.nblock);
	header->header.k = le16toh(header->header.k);
	header->header.m = le16toh(header->header.m);
	header->header.nbyte = le64toh(header->header.nbyte);
}

static void bef_unprepare_frag_header(struct bef_frag_header *header)
{
	header->block_num = le32toh(header->block_num);
	header->frag_num = le16toh(header->frag_num);
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

static int bef_get_backend(bef_par_t par_t)
{
	int ret;

	switch(par_t) {
	case BEF_PAR_J_V_RS:
	case BEF_PAR_J_C_RS:
	case BEF_PAR_LE_V_RS:
	case BEF_PAR_I_V_RS:
	case BEF_PAR_I_C_RS:
		ret = BEF_BACKEND_LIBERASURECODE;
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
 * it's a primary or secondary block. Second of all, the number of padded bytes
 * to the input packets to make it all fit nicely and smugly.
 */
static int bef_encode_libfec(const char *input, size_t inbyte, char **data,
			     char **parity, size_t *frag_len, int k, int m)
{
	struct bef_fec_header header;
	size_t size = inbyte / k + inbyte % k; //Size of each data fragment
	unsigned int block_nums[m];
	fec_t *context;
	header.pbyte = inbyte % k;
	*frag_len = sizeof(header) + size;

	/* Allocate our arrays, moving the pointer past the header. I know, it's
	 * a bit hacky, but it works!
	 */
	for(int i = 0; i < k; i++) {
		*(data + i) = malloc(size + sizeof(header));
		header.block_num = i;

		if(i < k - 1) {
			memcpy(*(data + i), &header, sizeof(header));
			memcpy(*(data + i) + sizeof(header),
			       input + i * (size - header.pbyte),
			       size - header.pbyte);
			memset(*(data + i) + sizeof(header) + size - header.pbyte,
			       '\0', header.pbyte);
		} else {
			memcpy(*(data + i), &header, sizeof(header));
			memcpy(*(data + i) + sizeof(header),
			       input + i * (size - header.pbyte), size);
		}

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
	uint32_t pbyte = 0;
	char *tmp; //To avoid duplicate paths later
	*onbyte = 0; //Unknown as of now

	/* See the odd one out and allocate an output */
	for(uint16_t i = 0; i < frag_len; i++) {
		memcpy(&header, *(frags+i), sizeof(header));
		if(header.block_num != i)
			out_arr[found++] = malloc(size);
		/* Get the size of the output buffer on first primary packet */
		else if(*onbyte == 0 && (i != frag_len - 1 || frag_len == 1)) {
			pbyte = header.pbyte;
			*onbyte = (size - pbyte) * k + pbyte;
		}
		block_nums[i] = header.block_num;

		/* Do our evil pointer arithmetic hackery again */
		*(frags + i) += sizeof(header);
	}

	/* Allocate our output buffer */
	*output = malloc(*onbyte);

	fec_init(); //Same question as before, guess we'll find out

	context = fec_new(k, k+m);

	fec_decode(context, (unsigned char **) frags,
		   (unsigned char **) out_arr, block_nums, size);

	/* Write to output buffer */
	found = 0;
	for(uint16_t i = 0; i < frag_len; i++) {
		if(block_nums[i] == i)
			tmp = *(frags + i);
		else
			tmp = out_arr[found++];

		if(i < frag_len - 1)
			memcpy(*output + i * (size - pbyte), tmp, size - pbyte);
		else
			memcpy(*output + i * (size - pbyte), tmp, size);
	}

	/* Undo our pointer hackery */
	for(uint16_t i = 0; i < frag_len; i++)
		*(frags + i) -= sizeof(header);

	fec_free(context);
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

/* We use XXHASH again, because it's pretty fast for small inputs (github
 * benchmark says about ~140M/s for 64bit inputs). Perhaps we could use
 * something else for our PRNG algorithm, but I feel this is good enough
 *
 * Due to improper use of modulus, it is NOT perfectly uniformly random, but
 * it's *random enough*
 */
static uint64_t bef_par_rand(uint64_t value, uint64_t range, uint32_t seed)
{
	uint8_t input[12];
	XXH64_hash_t hash;

	memcpy(input, &seed, 4);
	memcpy(input+4, &value, 8); //Use our value in our input to hash

	hash = XXH3_64bits(input, 12);
	hash = hash % range; //Keep it in range
	return (uint64_t) hash;
}

/* Construction of a shuffled table using the Fisher-Yates algorithm, with the
 * given index being stored in the resulting index. Should be a uniform
 * distribution if bef_par_rand() is uniformly random for its range
 */
static void bef_construct_par_tbl(uint64_t m, uint32_t seed)
{
	uint64_t j;
	uint64_t tmp;

	/* First allocate the table */
	m_arr = bef_malloc(m * sizeof(*m_arr));

	/* Allocate the values accordingly */
	for(uint64_t i = 0; i < m; i++)
		m_arr[i] = i;

	/* Fisher-Yates */
	for(uint64_t i = m - 1; i > 0; i--) {
		j = bef_par_rand(i, i + 1, seed); //Use index as hashed value
		tmp = m_arr[i];
		m_arr[i] = m_arr[j];
		m_arr[j] = tmp;
	}
}

/* m_arr MUST ALREADY BE ALLOCATED!!! */
static uint64_t bef_lookup_par(uint64_t m_index)
{
	return m_arr[m_index];
}

static off_t bef_par_location(uint16_t k, uint16_t m, uint64_t nbyte,
			      uint64_t m_index)
{
	uint64_t tmp;
	off_t ret;

	tmp = m_index / m; //multiple of m that come before m_index
	tmp *= (k + m) * nbyte; //Number of blocks that came before us
	if(m_index % m == 0)
		tmp += (k + m - 1) * nbyte; //We are the last fragment
	else
		tmp += (k + m_index % m - 1) * nbyte; //We are the nth fragment
	ret = (off_t) tmp;
	if(ret > 0)
		return (off_t) ret;
	else
		return -BEF_ERR_OVERFLOW;
}

static int bef_construct_header(int input, char *ibuf, size_t ibuf_s,
				bef_par_t par_t, uint16_t k, uint16_t m,
				uint32_t nblock, struct bef_header *header)
{
	int ret;
	ssize_t rret;
	char **data = bef_malloc(k * sizeof(*data));
	char **parity = bef_malloc(m * sizeof(*parity));
	size_t frag_len;

	/* Our lovely, sexy, beautiful magic number */
	memcpy(header->magic, bef_magic, 7);
	/* Generate our seed for our reproducible hash table */
	getrandom(&(header->header.seed), sizeof(header->header.seed), 0);
	header->header.nblock = nblock;
	header->header.par_t = par_t;
	header->header.k = k;
	header->header.m = m;
	header->header.nseg = 1; //We don't know how many yet

	/* To get nbyte, which depends on the backend used, we are going to
	 * construct the first block twice (so I don't have to lug around a
	 * evil output buffer or worse, two char **s). I know, I know! It's evil
	 * and wrong, but unless you want like 4 fragments in total, it'll be
	 * fine!
	 */
	rret = read(input, ibuf, ibuf_s);
	if(rret != ibuf_s) {
		ret = -BEF_ERR_READERR;
		goto out;
	}
	ret = bef_encode_ecc(ibuf, ibuf_s, data, parity, &frag_len, k, m,
			     par_t);
	if(ret != 0)
		goto out;

	header->header.nbyte = (uint64_t) (frag_len + sizeof(struct bef_frag_header));

	/* And that's all folks! */

	bef_encode_free(data, parity, k, m);
out:
	free(data);
	free(parity);
	return ret;
}

static int bef_construct_frag_h(char *input, size_t frag_len,
				uint32_t block_num, uint16_t frag_num,
				bef_hash_t hash_t, uint64_t nbyte,
				struct bef_frag_header *header)
{
	int ret;
	header->block_num = block_num;
	header->frag_num = frag_num;
	nbyte -= (uint64_t) (frag_len + sizeof(*header));
	if(nbyte > 0)
		header->pbyte = nbyte;
	else
		header->pbyte = 0;

	ret = bef_digest(input, frag_len, header->hash, hash_t);

	return ret;
}

static int bef_construct_frag(char *output, char *body, size_t frag_len,
			      uint32_t block_num, uint16_t frag_num,
			      bef_hash_t hash_t, uint64_t nbyte)
{
	int ret;
	struct bef_frag_header header;
	size_t offset = 0;

	ret = bef_construct_frag_h(body, frag_len, block_num, frag_num, hash_t,
				   nbyte, &header);
	if(ret != 0)
		return ret;
	bef_prepare_frag_header(&header);
	memcpy(output, &header, sizeof(header));
	offset += sizeof(header);
	memcpy(output + offset, body, frag_len);
	offset += frag_len;
	memset(output + offset, '\0', header.pbyte);

	return 0;
}

/* output MUST BE AT LEAST (k+m) * nbyte large,
 * also frag_len + sizeof(bef_header) MUST EQUAL nbyte!!!
 */
static int bef_construct_block(char *output, char **data, char **parity,
			       uint16_t k, uint16_t m, size_t frag_len,
			       uint32_t block_num, uint64_t nbyte,
			       bef_hash_t hash_t)
{
	int ret;
	size_t offset = 0;
	uint16_t frag_num = 0;

	for(uint16_t i = 0; i < k; i++) {
		ret = bef_construct_frag(output + offset, *(data + i), frag_len,
					 block_num, frag_num++, hash_t, nbyte);
		if(ret != 0)
			return ret;
		offset += (size_t) nbyte;
	}
	for(uint16_t i = 0; i < m; i++) {
		ret = bef_construct_frag(output + offset, *(parity + i),
					 frag_len, block_num, frag_num++,
					 hash_t, nbyte);
		if(ret != 0)
			return ret;
		offset += (size_t) nbyte;
	}

	return 0;
}

static int bef_encode_block(char *ibuf, size_t ibuf_s, char *obuf,
			    uint32_t block_num, bef_hash_t hash_t,
			    struct bef_real_header *header)
{
	int ret;
	char **data = bef_malloc(header->k * sizeof(*data));
	char **parity = bef_malloc(header->m * sizeof(*parity));
	size_t frag_len;

	ret = bef_encode_ecc(ibuf, ibuf_s, data, parity, &frag_len, header->k,
			     header->m, header->par_t);
	if(ret != 0)
		goto out;
	ret = bef_construct_block(obuf, data, parity, header->k, header->m,
				  frag_len, block_num, header->nbyte,
				  hash_t);
	bef_encode_free(data, parity, header->k, header->m);
	if(ret != 0)
		goto out;

out:
	free(data);
	free(parity);
	return ret;
}

/* I wish there was a way to swap without 3 (4 without cache) seeks ;_; */
static int bef_construct_swap(int output, char *buf_a, char *buf_b, off_t seg,
			      uint64_t a, uint64_t b,
			      uint16_t k, uint16_t m, uint64_t nbyte)
{
	ssize_t bret;
	off_t off_a;
	off_t off_b;

	/* Get our swapees */
	off_a = bef_par_location(k, m, nbyte, a);
	lseek(output, seg + off_a, SEEK_SET);
	bret = read(output, buf_a, nbyte); //Our original
	if(bret != nbyte)
		return -BEF_ERR_READERR;

	off_b = bef_par_location(k, m, nbyte, b);
	lseek(output, seg + off_b, SEEK_SET);
	bret = read(output, buf_b, nbyte); //Our swapee
	if(bret != nbyte)
		return -BEF_ERR_READERR;

	/* Write our swapees */
	lseek(output, seg + off_b, SEEK_SET); //Go right back!
	bret = write(output, buf_a, nbyte); //RIP fragment b
	if(bret != nbyte)
		return -BEF_ERR_WRITEERR;

	lseek(output, seg + off_a, SEEK_SET);
	bret = write(output, buf_b, nbyte); //RIP fragment a
	if(bret != nbyte)
		return -BEF_ERR_WRITEERR;

	return 0;
}

/* Shuffling algorithm that goes like thus, treating all parities as one giant
 * array of values with a index relative to the total number of parities.
 *
 * 1. Calculate index
 * 2. Use some lookup algorithm to get the new random index
 * 3. If random index and real index are not equal, swap and goto 1 with new
 *    index
 * 4. Continue to next index from real index.
 * 5. Goto 1 until all indexes are exhausted.
 *
 * Note that m_arr obviously must be constructed by this point.
 *
 * This algorithm is very very inefficient, and is one of the main source of
 * time taken up by this program (it and the erasure coding
 * interface/libraries). Not sure how to swap the arrays to their correct order
 * in a more efficient way though, but perhaps I'm just being stupid. Can't
 * exactly recommend this software until I find a better algorithm.
 */
static int bef_construct_shuffle(int output, off_t seg, uint16_t k, uint16_t m,
				 uint64_t nbyte, uint32_t nblock)
{
	int ret = 0;
	uint64_t m_index = 0; //First index
	uint64_t total_m = ((uint64_t) nblock) * m;
	char *buf_a = bef_malloc(nbyte);
	char *buf_b = bef_malloc(nbyte);
	/* Keep track of the current indices */
	uint64_t *c_arr = bef_malloc(total_m * sizeof(*c_arr));
	uint64_t tmp;

	/* Allocate current array to default values */
	for(uint64_t i = 0; i < total_m; i++)
		c_arr[i] = i;

	/* Transform to m_arr's ordering */
	for(uint64_t i = 0; i < total_m;) {
		m_index = bef_lookup_par(m_index);
		if(m_index != i) {
			ret = bef_construct_swap(output, buf_a, buf_b, seg,
						 i, m_index, k, m, nbyte);
			if(ret != 0)
				goto out;
			tmp = c_arr[i];
			c_arr[i] = c_arr[m_index];
			c_arr[m_index] = tmp;
		}
		else {
			m_index = c_arr[++i]; //index is equal, move forward
		}
	}
out:
	free(c_arr);
	free(buf_a);
	free(buf_b);
	return ret;
}

static int bef_construct_encode(int input, int output,
				char *ibuf, size_t ibuf_s, bef_hash_t hash_t,
				struct bef_header *head)
{
	int ret;
	ssize_t bret;
	struct bef_real_header *header = &(head->header);
	size_t obuf_s = (header->k + header->m) * header->nbyte;
	char *obuf = bef_malloc(obuf_s);
	uint32_t block_num = 0;
	off_t offset = (off_t) sizeof(struct bef_header);

	/* Redo very first block, source still in input */
	ret = bef_encode_block(ibuf, ibuf_s, obuf, block_num++, hash_t, header);
	if(ret != 0)
		goto out;

	bret = write(output, obuf, obuf_s);
	if(bret != obuf_s) {
		ret = -BEF_ERR_WRITEERR;
		goto out;
	}

	/* Eternal read loop incoming */
	while(1) {
		if(block_num == header->nblock && header->nblock != 0) {
			block_num = 0; //New Segment
			header->nseg++;
		}

		bret = read(input, ibuf, ibuf_s);
		if(bret == 0)
			break; //No more data to read!
		else if(bret < 0) {
			ret = -BEF_ERR_READERR;
			goto out;
		}

		ret = bef_encode_block(ibuf, bret, obuf, block_num++, hash_t,
				       header);
		if(ret != 0)
			goto out;

		bret = write(output, obuf, obuf_s);
		if(bret != obuf_s) {
			ret = -BEF_ERR_WRITEERR;
			goto out;
		}
	}

	/* Set real nblock */
	if(header->nblock == 0 && block_num > 0)
		header->nblock = block_num;

	/* Construct parity table */
	bef_construct_par_tbl(header->m * header->nblock, header->seed);

	/* Now we gotta shuffle the parities around using our hash map */
	for(uint64_t i = 0; i < header->nseg; i++) {
		ret = bef_construct_shuffle(output, offset, header->k,
					    header->m, header->nbyte,
					    header->nblock);
		if(ret != 0)
			goto out;
		offset += (off_t) (header->nblock * header->nbyte);
	}

out:
	free(m_arr); //May not exist, but is NULL otherwise so its all good
	free(obuf);
	free(ibuf);
	return ret;
}

/* Our lovely file constructor! Split in two parts ^_^ */
int bef_construct(int input, int output,
		  bef_par_t par_t, uint16_t k, uint16_t m, bef_hash_t hash_t,
		  uint32_t nblock, uint64_t bsize)
{
	int ret;
	ssize_t wret;
	char *ibuf;
	size_t ibuf_s;
	struct bef_header header;

	if(bsize == 0)
		bsize = BEF_BSIZE;
	if(par_t == 0)
		par_t = BEF_PAR_DEFAULT;
	if(hash_t == 0)
		hash_t = BEF_HASH_DEFAULT;
	if(k == 0)
		k = BEF_K_DEFAULT;
	if(m == 0)
		m = BEF_M_DEFAULT;

	/* Estimate size of our shared input buffer, using bsize and k */
	ibuf_s = bsize;
	ibuf = bef_malloc(sizeof(*ibuf) * ibuf_s);

	ret = bef_construct_header(input, ibuf, ibuf_s, par_t, k, m, nblock,
				   &header);
	if(ret != 0)
		return ret;

	/* Seek ahead of where header will be, it's still not done! */
	lseek(output, sizeof(header), SEEK_SET);

	/* ibuf should be freed by this function, so no need to check */
	ret = bef_construct_encode(input, output, ibuf, ibuf_s, hash_t,
				   &header);
	if(ret != 0)
		return ret;

	/* let's now go back to the beginning, and finally write the header */
	lseek(output, 0, SEEK_SET);

	/* Let prepare our header, converting everything to Little Endian */
	bef_prepare_header(&header);

	/* let's now compute our hash! */
	header.hash_t = hash_t;
	ret = bef_digest((char *) &(header.header), sizeof(header.header),
			 header.hash, hash_t);
	if(ret != 0)
		return ret;

	/* Let's now make our backup header, in case freaky things happen */
	memcpy(&(header.header_b), &(header.header), sizeof(header.header));

	/* Write our header to output */
	wret = write(output, &header, sizeof(header));
	if(wret != sizeof(header))
		return -BEF_ERR_WRITEERR;

	return ret;
}

static int bef_verify_fragment(char *frag, uint64_t nbyte, bef_hash_t hash_t)
{
	int ret;
	uint8_t hash[BEF_HASH_SIZE];
	struct bef_frag_header header;

	/* Copy over our header */
	memcpy(&header, frag, sizeof(header));
	bef_unprepare_frag_header(&header); //Make it host endian

	/* Get our hash */
	if(header.pbyte >= nbyte) //Thereotically Impossible
		return -BEF_ERR_INVALHEAD;
	ret = bef_digest(frag + sizeof(header),
			 nbyte - header.pbyte - sizeof(header), hash, hash_t);
	if(ret != 0)
		return ret;

	/* Compare our two hashes */
	if(memcmp(header.hash, hash, sizeof(hash)) != 0) {
		return -BEF_ERR_INVALHASH;
	} else
		return 0;
}

static int bef_deconstruct_buffers(char ***buf_arr, uint16_t km,
				    uint64_t nbyte)
{
	if(km == 0)
		return -BEF_ERR_INVALINPUT;

	*buf_arr = bef_malloc(km * sizeof(*(*buf_arr)));
	for(uint16_t i = 0; i < km; i++)
		*(*buf_arr + i) = bef_malloc(nbyte);

	return 0;
}

static void bef_deconstruct_free(char **buf_arr, uint16_t km)
{
	for(uint16_t i = 0; i < km; i++)
		free(*(buf_arr + i));
	free(buf_arr);
}

static int bef_deconstruct_header(int input, struct bef_real_header *header,
				  bef_hash_t *hash_t)
{
	int ret;
	ssize_t bret;
	struct bef_header head;
	uint8_t hash[BEF_HASH_SIZE];

	bret = read(input, &head, sizeof(head));
	if(bret != sizeof(head))
		return -BEF_ERR_READERR;

	bef_unprepare_header(&head); //Gotta get right endianness

	if(memcmp(head.magic, bef_magic, 7) != 0)
		return -BEF_ERR_INVALHEAD; //WTF, it's not our BABE!?
	*hash_t = head.hash_t;
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

	return 0;
}

static int bef_get_parity(int input, char *output, char *ibuf,
			  uint32_t block_num, uint16_t m,
			  struct bef_real_header header, bef_hash_t hash_t,
			  off_t seg)
{
	int ret = -BEF_ERR_INVALHASH; //We are already at a invalid hash
	uint64_t frag_b = header.nbyte - sizeof(struct bef_frag_header);
	uint64_t m_index;
	off_t orig = lseek(input, 0, SEEK_CUR); //Get the original offset
	off_t offset;
	ssize_t rret;

	for(; ret == -BEF_ERR_INVALHASH; m++) {
		if(m >= header.m)
			return -BEF_ERR_NEEDMORE;

		m_index = block_num * header.m + m;
		m_index = bef_lookup_par(m_index);
		offset = bef_par_location(header.k, header.m, header.nbyte,
					  m_index);

		lseek(input, seg + offset, SEEK_SET);
		rret = read(input, ibuf, header.nbyte);
		if(rret != header.nbyte)
			return -BEF_ERR_READERR;
		ret = bef_verify_fragment(ibuf, header.nbyte, hash_t);
	}

	if(ret != 0)
		return ret;
	else {
		lseek(input, orig, SEEK_SET); //Go back to the original
		memcpy(output, ibuf + sizeof(struct bef_frag_header), frag_b);
		return 0;
	}
}

static int bef_deconstruct_block(int input, char **output, size_t *onbyte,
				 struct bef_real_header header,
				 bef_hash_t hash_t, off_t seg)
{
	int ret;
	ssize_t bret;
	char **buf_arr;
	struct bef_frag_header frag_h;
	char *ibuf = bef_malloc(header.nbyte);
	uint64_t frag_b = header.nbyte - sizeof(frag_h);
	uint16_t m = 0;

	ret = bef_deconstruct_buffers(&buf_arr, header.k + header.m, frag_b);
	if(ret != 0)
		goto out;
	for(uint16_t i = 0; i < header.k; i++) {
		bret = read(input, ibuf, header.nbyte);
		if(bret != header.nbyte) {
			ret = -BEF_ERR_READERR;
			goto buffer_cleanup;
		}

		/* Get our fragment header */
		memcpy(&frag_h, ibuf, sizeof(frag_h));
		bef_unprepare_frag_header(&frag_h);

		ret = bef_verify_fragment(ibuf, header.nbyte, hash_t);
		if(ret == -BEF_ERR_INVALHASH) { //Gotta get parity
			ret = bef_get_parity(input, *(buf_arr + i), ibuf,
					     frag_h.block_num, m++, header,
					     hash_t, seg);
			if(ret != 0)
				goto buffer_cleanup;
		} else if(ret != 0)
				goto buffer_cleanup;
		else
			memcpy(*(buf_arr + i), ibuf + sizeof(frag_h),
			       frag_b - frag_h.pbyte);
	}

	/* Skip the parities */
	lseek(input, (off_t) header.m * header.nbyte, SEEK_CUR);

	/* And now after that digusting loop */
	ret = bef_decode_ecc(buf_arr, header.k, frag_b - frag_h.pbyte, output,
			     onbyte, header.k, header.m, header.par_t);

buffer_cleanup:
	bef_deconstruct_free(buf_arr, header.k + header.m);
out:
	free(ibuf);
	return ret;
}

/* Surprisingly simpler than encoding, but still takes up a far too many lines
 * of code
 */
int bef_deconstruct(int input, int output)
{
	int ret;
	ssize_t bret;
	struct bef_real_header header;
	bef_hash_t hash_t;
	char *obuf;
	size_t obuf_s;
	off_t seg_off = (off_t) sizeof(struct bef_header);

	/* Get our heaer and verify its sanity */
	ret = bef_deconstruct_header(input, &header, &hash_t);
	if(ret != 0)
		goto out;

	/* Generate parity lookup table */
	bef_construct_par_tbl(header.m * header.nblock, header.seed);

	/* Now read each block of each segment, skipping parities unless
	 * absolutely necessary. This allows for us to reconstruct as fast as
	 * possible due to the linear arrangement of the data. Our buffer will
	 * be the array of (k+m) fragments, each buffer being nbyte size,
	 * allocated by bef_deconstruct_buffers() and freed by
	 * bef_deconstruct_free().
	 */
	for(uint64_t seg = 0; seg < header.nseg; seg++) {
		for(uint32_t block = 0; block < header.nblock; block++) {
			ret = bef_deconstruct_block(input, &obuf, &obuf_s,
						    header, hash_t, seg_off);
			if(ret != 0)
				goto out;
			bret = write(output, obuf, obuf_s);
			bef_decode_free(obuf);
			if(bret != obuf_s) {
				ret = -BEF_ERR_WRITEERR;
				goto out;
			}
		}
		seg_off += (off_t) (header.nblock * header.nbyte);
	}

out:
	free(m_arr); //NULL so all good!
	return ret;
}

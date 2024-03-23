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

#include "bef.h"
#include "zfec.h"

#ifdef _OPENMP
#include <omp.h>
#endif
#ifdef BEF_CM256CC
#include "cm256.h"
#endif
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
#ifdef BEF_OPENFEC
#include <openfec/lib_common/of_openfec_api.h>
#endif
#ifdef BEF_LEOPARD
#include <leopard.h>
#endif
#ifdef BEF_WIREHAIR
#include <wirehair/wirehair.h>
#endif

#include <string.h>
#include <xxhash.h>
#include <stdlib.h>
#include <assert.h>
#include <unistd.h>
#include <sys/random.h>
#include <endian.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/param.h>

#define BEF_SAFE_READ	0
#define BEF_SAFE_WRITE	1

#define BEF_VERIFY_FRAG_H	0
#define BEF_VERIFY_FRAG_B	1

#define BEF_SCAN_FORWARDS	0
#define BEF_SCAN_BACKWARDS	1

#define BEF_SPAR_ENCODE		0
#define BEF_SPAR_DECODE		1
#define BEF_SPAR_MAXFRA		2
#define BEF_SPAR_INIT		4
#define BEF_SPAR_DESTRO		5
#define BEF_SPAR_MULTIT		6
#define BEF_SPAR_MAXNUM		7

#define BEF_RECON_REPLACE	0
#define BEF_RECON_NULL		1

/* Struct for libfec header */
struct bef_fec_header {
	uint32_t block_num;
	uint32_t nbyte; //For backends that have variable number of bytes
};

#ifdef BEF_LIBERASURECODE
static int bef_desc = -1;
#endif
static fec_t *bef_context = NULL;

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

static int bef_liberasurecode_init(bef_par_t par_t, uint16_t k, uint16_t m)
{
	ec_backend_id_t backend_id;
	struct ec_args args = {0};
	int ret;
	args.k = k;
	args.m = args.hd = m; //Only support RS for now

	if(bef_desc == -1) {
		backend_id = bef_liberasurecode_par_switch(par_t);
		if(backend_id == EC_BACKENDS_MAX)
			return -BEF_ERR_INVALINPUT;

		ret = liberasurecode_backend_available(backend_id);
		if(ret < 0)
			return -ret;

		bef_desc = liberasurecode_instance_create(backend_id, &args);
		if(bef_desc < 0)
			return -bef_desc;
	}

	return 0;
}
#endif

static void bef_fec_init(uint16_t k, uint16_t m)
{
	fec_init();

	bef_context = fec_new(k, k+m);
}

#ifdef BEF_OPENFEC
static int bef_openfec_init(of_session_t **session, uint16_t k, uint16_t m,
			    uint64_t nbyte)
{
	of_status_t ret;
	of_parameters_t params = {k, m, nbyte};

	ret = of_create_codec_instance(session,
				       OF_CODEC_REED_SOLOMON_GF_2_8_STABLE,
				       OF_ENCODER_AND_DECODER, 0);
	if(ret != OF_STATUS_OK)
		return -BEF_ERR_OPENFEC;

	ret = of_set_fec_parameters(*session, &params);
	if(ret != OF_STATUS_OK)
		return -BEF_ERR_OPENFEC;
	else
		return 0;
}
#endif

#ifdef BEF_LEOPARD
static int bef_leopard_init(void)
{
	if(leo_init() != 0)
		return -BEF_ERR_LEOPARD;
	return 0;
}
#endif

#ifdef BEF_WIREHAIR
static int bef_wirehair_init(void)
{
	if(wirehair_init() != 0)
		return -BEF_ERR_WIREHAIR;
	return 0;
}
#endif

#ifdef BEF_LIBERASURECODE
static int bef_liberasurecode_destroy(void)
{
	int ret;

	ret = liberasurecode_instance_destroy(bef_desc);
	if(ret < 0)
		return -ret;
	else
		return 0;
}
#endif

static void bef_fec_destroy(void)
{
	fec_free(bef_context);
}

#ifdef BEF_OPENFEC
static void bef_openfec_destroy(of_session_t *session)
{
	of_release_codec_instance(session);
}
#endif

/* Our great padding function from the sky. Gives the amount of padded bytes
 * that would satisfy these properties.
 *
 * 1.	Divisible by il_n
 * 2.	Divisible by k
 * 3.	Divisible by 64 (for Leopard's Reed Solomon)
 * 4.	Large enough to hold inbyte.
 */
static uint64_t bef_sky_padding(size_t inbyte,
				uint16_t il_n, uint16_t k, uint64_t bsize)
{
	uint64_t common = (uint64_t) k * il_n * 64;
	uint64_t pbyte = il_n * bsize;

	if(pbyte % common != 0)
		pbyte += common - pbyte % common;

	if(inbyte < pbyte)
		pbyte -= inbyte;
	else
		pbyte = 0;

	if(bef_vflag > 1)
		fprintf(stderr, "Padded %lu bytes to %zu input bytes\n",
			pbyte, inbyte);

	return pbyte;
}

static ssize_t bef_safe_rw(int fd, char *buf, size_t nbyte, uint8_t flag)
{
	ssize_t ret = 1; //Set to > 0 for loop
	ssize_t offset = 0;

	/* Keep trying if interrupted or told to try again, or if buffer is not
	 * full
	 */
	while((ret == -1 && (errno == EAGAIN || errno == EINTR)) ||
	      (offset != nbyte && ret > 0)) {
		if(flag == BEF_SAFE_READ) {
			ret = read(fd, buf + offset, nbyte - offset);
			if(bef_vflag > 1)
				fprintf(stderr, "read %zd bytes from %d, amount left %zu\n",
					ret, fd, nbyte - offset - ret);
		} else {
			ret = write(fd, buf + offset, nbyte - offset);
			if(bef_vflag > 1)
				fprintf(stderr, "wrote %zd bytes to %d, amount left %zu\n",
					ret, fd, nbyte - offset - ret);
		}

		if(ret > 0) {
			if(SSIZE_MAX - offset > ret) //to check for overflow
				offset += ret;
			else
				return -1;
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
	header->block_num = htole64(header->block_num);
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
	header->block_num = le64toh(header->block_num);
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

	if(bef_vflag > 2)
		fprintf(stderr,
			"Hashing %zu bytes of input with hash type %u\n",
			nbyte, hash_t);

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
static int bef_encode_liberasurecode(const char *input, size_t inbyte,
				     char **data, char **parity,
				     size_t *frag_len,
				     struct bef_real_header header)
{
	int ret;
	char **tmp_data;
	char **tmp_parity;

	ret = liberasurecode_encode(bef_desc, input, inbyte, &tmp_data, &tmp_parity,
				    (uint64_t *) frag_len);
	if(ret < 0)
		return -ret;

	/* Copy over the results */
	for(int i = 0; i < header.k; i++) {
		*(data + i) = bef_malloc(*frag_len);
		memcpy(*(data + i), *(tmp_data + i), *frag_len);
	}
	for(int i = 0; i < header.m; i++) {
		*(parity + i) = bef_malloc(*frag_len);
		memcpy(*(parity + i), *(tmp_parity + i), *frag_len);
	}

	/* Free our given buffers */
	ret = liberasurecode_encode_cleanup(bef_desc, tmp_data, tmp_parity);
	if(ret < 0) {
		ret = -ret;
		bef_encode_free(data, parity, header.k, header.m);
	}

	return ret;
}
#endif

/* Due to this being low level, we'll have to add some pivotal metadata
 * ourselves as a header. First of all, the block number of the block, and since
 * we know how many k there are, that's all we need to know regarding whether
 * it's a primary or secondary block.
 */
static int bef_encode_libfec(const char *input, size_t inbyte, char **data,
			     char **parity, size_t *frag_len,
			     struct bef_real_header header)
{
	struct bef_fec_header frag_h = {0};
	size_t size = inbyte / header.k; //Size of each data fragment, prepadded
	unsigned int block_nums[header.m];
	*frag_len = sizeof(frag_h) + size;

	/* Allocate our arrays, moving the pointer past the header. I know, it's
	 * a bit hacky, but it works!
	 */
	for(int i = 0; i < header.k; i++) {
		*(data + i) = bef_malloc(size + sizeof(frag_h));
		frag_h.block_num = i;

		memcpy(*(data + i), &frag_h, sizeof(frag_h));
		memcpy(*(data + i) + sizeof(frag_h), input + i * size, size);

		*(data + i) += sizeof(frag_h); //Evil and Satanic
	}
	for(int i = 0; i < header.m; i++) {
		*(parity + i) = bef_malloc(size + sizeof(frag_h));
		block_nums[i] = header.k + i;
		frag_h.block_num = header.k + i;
		memcpy(*(parity + i), &frag_h, sizeof(frag_h));
		*(parity + i) += sizeof(frag_h); //Evil and Satanic
	}

	/* I rather live with the warning than add a million consts */
	fec_encode(bef_context, (unsigned char **) data,
		   (unsigned char **) parity, block_nums, header.m, size);

	/* Now set the pointers back */
	for(int i = 0; i < header.k; i++)
		*(data + i) -= sizeof(frag_h);
	for(int i = 0; i < header.m; i++)
		*(parity + i) -= sizeof(frag_h);

	return 0;
}

#ifdef BEF_CM256CC
/* We need header information regarding the block number (Index in this case).
 * The API struct is sadly not padded and thus is undefined in many cases.
 * However, I still desire to keep compatibility with the actual API interface,
 * so we'll use our trusty bef_fec_header struct for this essential metadata.
 */
static int bef_encode_cm256(const char *input, size_t inbyte, char **data,
			    char **parity, size_t *frag_len,
			    struct bef_real_header header)
{
	int ret;
	bef_cm256_encoder_params params = {header.k, header.m,
					inbyte / header.k};
	bef_cm256_block iblock[header.k];
	char *block_buf = bef_malloc((uint64_t) header.m * params.BlockBytes);
	struct bef_fec_header frag_h = {0};
	*frag_len = params.BlockBytes + sizeof(frag_h);

	/* Allocate our arrays */
	for(uint16_t i = 0; i < header.k; i++) {
		frag_h.block_num = i;
		*(data + i) = bef_malloc(params.BlockBytes + sizeof(frag_h));

		memcpy(*(data + i), &frag_h, sizeof(frag_h));
		memcpy(*(data + i) + sizeof(frag_h),
		       input + i * params.BlockBytes, params.BlockBytes);
	}
	for(uint16_t i = 0; i < header.m; i++) {
		frag_h.block_num = header.k + i;
		*(parity + i) = bef_malloc(params.BlockBytes + sizeof(frag_h));

		memcpy(*(parity + i), &frag_h, sizeof(frag_h));
	}

	/* Set our original blocks */
	for(uint16_t i = 0; i < header.k; i++) {
		iblock[i].Block = *(data + i) + sizeof(frag_h);
		iblock[i].Index = i;
	}

	ret = bef_cm256_encode(params, iblock, block_buf);
	if(ret != 0) {
		bef_encode_free(data, parity, header.k, header.m);
		ret = -BEF_ERR_CM256;
		goto out;
	}

	/* Copy over the parities */
	for(uint16_t i = 0; i < header.m; i++)
		memcpy(*(parity + i) + sizeof(frag_h),
		       block_buf + i * params.BlockBytes, params.BlockBytes);

out:
	free(block_buf);
	return ret;
}
#endif

#ifdef BEF_OPENFEC
/* Like with other relatively low level libraries, this requires we know the
 * block number. So we use our good old trusty bef_fec_header to provide this
 * key information.
 */
static int bef_encode_openfec(const char *input, size_t inbyte, char **data,
			      char **parity, size_t *frag_len,
			      struct bef_real_header header)
{
	int ret;
	of_status_t oret;
	of_session_t *session = NULL;
	char *symbol_tbl[header.k + header.m];
	struct bef_fec_header frag_h = {0};
	size_t size = inbyte / header.k;
	uint16_t flag = 0;
	*frag_len = size + sizeof(frag_h);

	ret = bef_openfec_init(&session, header.k, header.m, size);
	if(ret != 0)
		return ret;

	/* Allocate our arrays and set their pointers in the symbol table
	 * appropiately. Likewise, also encode during this step, as we process
	 * each symbol individually.
	 */
	for(uint16_t i = 0; i < header.k; i++) {
		frag_h.block_num = i;
		*(data + i) = bef_malloc(sizeof(frag_h) + size);
		memcpy(*(data + i), &frag_h, sizeof(frag_h));
		memcpy(*(data + i) + sizeof(frag_h), input + i * size, size);
		symbol_tbl[i] = *(data + i) + sizeof(frag_h);
	}
	for(uint16_t i = 0; i < header.m && flag == 0; i++) {
		frag_h.block_num = header.k + i;
		*(parity + i) = bef_malloc(sizeof(frag_h) + size);
		memcpy(*(parity + i), &frag_h, sizeof(frag_h));
		symbol_tbl[header.k + i] = *(parity + i) + sizeof(frag_h);

		oret = of_build_repair_symbol(session, (void **) symbol_tbl,
					     header.k + i);
		if(oret != OF_STATUS_OK)
			flag = i;
	}

	bef_openfec_destroy(session);

	if(flag != 0) {
		bef_encode_free(data, parity, header.k, flag);
		return -BEF_ERR_OPENFEC;
	} else {
		return 0;
	}
}
#endif

#ifdef BEF_LEOPARD
/* Like a bunch of others, this appears to be highly sensitive to ordering,
 * reading the rather sparse API it says lost data should be set to NULL (as
 * like openfec), which implies that it must also be in order. Thus, we'll use
 * our trusty bef_fec_header again. Damn, who knew needing block numbers was
 * going to be so ubiquitious? Perhaps liberasurecode is unique in how much
 * stuff it does for us ^_^.
 */
static int bef_encode_leopard(const char *input, size_t inbyte, char **data,
			      char **parity, size_t *frag_len,
			      struct bef_real_header header)
{
	LeopardResult res;
	uint32_t work_count;
	char **work_data;
	struct bef_fec_header frag_h = {0};
	uint64_t size = inbyte / header.k;
	*frag_len = size + sizeof(frag_h);

	/* Leopard only works when m <= k */
	if(header.m > header.k)
		return -BEF_ERR_INVALINPUT;

	work_count = leo_encode_work_count(header.k, header.m);
	work_data = bef_malloc(work_count * sizeof(*work_data));

	/* Copy over our original buffers. Also do some evil pointer arithmetic
	 * so we'll be able to use these arrays in the encode function
	 */
	for(uint16_t i = 0; i < header.k; i++) {
		frag_h.block_num = i;
		*(data + i) = bef_malloc(size + sizeof(frag_h));

		memcpy(*(data + i), &frag_h, sizeof(frag_h));
		memcpy(*(data + i) + sizeof(frag_h), input + i * size, size);
		*(data + i) += sizeof(frag_h);
	}
	for(uint16_t i = 0; i < header.m; i++) {
		frag_h.block_num = header.k + i;
		*(parity + i) = bef_malloc(size + sizeof(frag_h));

		memcpy(*(parity + i), &frag_h, sizeof(frag_h));
		*(parity + i) += sizeof(frag_h);
	}
	for(uint32_t i = 0; i < work_count; i++)
		*(work_data + i) = bef_malloc(size);

	res = leo_encode(size, header.k, header.m, work_count, data,
			 (void **) work_data);

	for(uint32_t i = 0; i < work_count; i++) {
		if(i < header.m)
			memcpy(*(parity + i), *(work_data + i), size);
		free(*(work_data + i));
	}
	free(work_data);

	/* Undo our hackery */
	for(uint16_t i = 0; i < header.k; i++)
		*(data + i) -= sizeof(frag_h);
	for(uint16_t i = 0; i < header.m; i++)
		*(parity + i) -= sizeof(frag_h);

	if(res != Leopard_Success) {
		bef_encode_free(data, parity, header.k, header.m);
		return -BEF_ERR_LEOPARD;
	} else {
		return 0;
	}
}
#endif

#ifdef BEF_WIREHAIR
/* Another one where we need to store block numbers in a bef_fec_header. This
 * also has the prereq that k <= 64000, although an unlimited number of parities
 * can be produced.
 */
static int bef_encode_wirehair(const char *input, size_t inbyte, char **data,
			       char **parity, size_t *frag_len,
			       struct bef_real_header header)
{
	WirehairResult res;
	WirehairCodec codec = NULL;
	uint64_t size = inbyte / header.k;
	struct bef_fec_header frag_h = {0};
	*frag_len = size + sizeof(frag_h);

	if(size > UINT32_MAX || (header.k > 64000 || header.k < 2))
		return -BEF_ERR_INVALINPUT;

	/* Allocate our arrays */
	for(uint16_t i = 0; i < header.k; i++) {
		frag_h.block_num = i;
		frag_h.nbyte = size;
		*(data + i) = bef_malloc(size + sizeof(frag_h));

		memcpy(*(data + i), &frag_h, sizeof(frag_h));
		memcpy(*(data + i) + sizeof(frag_h), input + i * size, size);
	}
	for(uint16_t i = 0; i < header.m; i++) {
		/* We need to zero out the parities in case nbyte < frag_b */
		*(parity + i) = bef_calloc(1, size + sizeof(frag_h));
	}

	/* Create our context and encode our parities */
	codec = wirehair_encoder_create(0, input, inbyte, size);
	if(codec == NULL) {
		bef_encode_free(data, parity, header.k, header.m);
		return -BEF_ERR_WIREHAIR;
	}

	for(uint16_t i = 0; i < header.m; i++) {
		frag_h.block_num = header.k + i;

		res = wirehair_encode(codec, header.k + i,
				      *(parity + i) + sizeof(frag_h), size,
				      &(frag_h.nbyte));
		if(res != Wirehair_Success) {
			bef_encode_free(data, parity, header.k, header.m);
			wirehair_free(codec);
			return -BEF_ERR_WIREHAIR;
		}

		memcpy(*(parity + i), &frag_h, sizeof(frag_h));
	}

	wirehair_free(codec);
	return 0;
}
#endif

/* Reconstructs a given array of fragments with a bef_fec_header.
 *
 * flag has special behaviors depending on what it is set.
 * If flag is set to BEF_RECON_NULL, then it will set the ones not found to NULL
 * and NOT move the parities to them. Instead it will consider recon_arr to be
 * an array of k+m elements and include the parities in their correct index.
 * The given block number for that NULL element will be UINT32_MAX, something
 * a 16bit number like k or k+m could never reach.
 *
 * Returns the number of fragments not found (and replaced with recoveries)
 */
static uint32_t bef_decode_reconstruct(char **frags, uint32_t frag_len,
				       char **recon_arr, uint32_t *block_nums,
				       uint32_t k, uint16_t m,
				       uint8_t flag)
{
	uint32_t ret = 0;
	uint32_t bound = k;
	uint32_t found = 0;
	uint16_t counter = 0;
	uint16_t stack[m];
	struct bef_fec_header header;

	if(flag == BEF_RECON_NULL)
		bound = k + m;

	for(uint32_t i = 0; i + found < k + m;) {
		memcpy(&header, *(frags + i), sizeof(header));

		if(header.block_num != i + found) {
			if(i + found < bound) {
				if(flag == BEF_RECON_NULL) {
					recon_arr[i + found] = NULL;
					block_nums[i + found] = UINT32_MAX;
				} else {
					stack[counter++] = i + found;
					ret++;
				}
			}

			found++;
			i--; //Keep going until we get to the correct index
		} else {
			/* Do our evil pointer arithmetic hackery again */
			*(frags + i) += sizeof(header);

			if(header.block_num < bound && i + found < bound) {
				recon_arr[header.block_num] = *(frags + i);
				block_nums[header.block_num] = header.block_num;
			} else if(counter > 0) {
				recon_arr[stack[--counter]] = *(frags + i);
				block_nums[stack[counter]] = header.block_num;
			}

			/* Undo our evil pointer arithmetic hackery */
			*(frags + i) -= sizeof(header);
		}

		/* Keep adding i if it is in range or has overflowed
		 * Since k+m can be at most 17 bits, it cannot reach UINT32_MAX
		 * unless it has overflowed when decrementing from i = 0
		 *
		 * When we have reached the end of the array, increment found as
		 * it indicates there are missing tail fragments. If flag does
		 * not contain BEF_RECON_NULL, and counter is equal to 0, then
		 * we end the loop's condition by setting found equal to the
		 * difference between i and k + m.
		 */
		if(i < frag_len - 1 || i == UINT32_MAX)
			i++;
		else if(i == frag_len - 1 &&
			(counter > 0 || flag == BEF_RECON_NULL))
			found++;
		else if(i == frag_len - 1 && counter == 0)
			found = k + m - i;
	}

	if(flag == BEF_RECON_NULL)
		return found;
	else
		return ret;
}

#ifdef BEF_LIBERASURECODE
static int bef_decode_liberasurecode(char **frags, uint32_t frag_len,
				     size_t frag_b,
				     char **output, size_t *onbyte,
				     struct bef_real_header header)
{
	int ret;
	char *tmp_output;
	uint64_t tmp_len;

	ret = liberasurecode_decode(bef_desc, frags, (int) frag_len,
				    (uint64_t) frag_b, 0, &tmp_output,
				    &tmp_len);
	if(ret < 0)
		return -ret;

	/* Copy over our data */
	*output = bef_malloc((size_t) tmp_len);
	*onbyte = tmp_len;
	memcpy(*output, tmp_output, *onbyte);

	/* free the liberasurecode structures */
	ret = liberasurecode_decode_cleanup(bef_desc, tmp_output);
	if(ret < 0) {
		ret = -ret;
		bef_decode_free(*output);
	} else if(ret > 0)
		ret = 0;

	return ret;
}
#endif

/* By default, our program automatically grabs the 'primary' blocks in
 * linear format, but we may've skipped blocks and grabbed parities instead. So
 * we need to reconstruct it in order of block number, replacing missing block
 * numbers with parities.
 */
static int bef_decode_libfec(char **frags, uint32_t frag_len, size_t frag_b,
			     char **output, size_t *onbyte,
			     struct bef_real_header header)
{
	char *out_arr[header.m]; //At most m outputs
	char *recon_arr[header.k]; //At most k outputs
	uint32_t block_nums[header.k];
	uint32_t found;
	char *tmp = NULL; //To avoid duplicate paths later
	size_t size = frag_b - sizeof(struct bef_fec_header);
	*onbyte = size * header.k;

	/* We are guaranteed at least k, and that's all we need */
	found = bef_decode_reconstruct(frags, header.k, recon_arr, block_nums,
				       (uint32_t) header.k, header.m,
				       BEF_RECON_REPLACE);
	for(uint32_t i = 0; i < found; i++)
		out_arr[i] = bef_malloc(size);

	/* Allocate our output buffer */
	*output = bef_malloc(*onbyte);

	if(found > 0) //We can just read directly if they're all good
		fec_decode(bef_context, (unsigned char **) recon_arr,
			   (unsigned char **) out_arr,
			   (unsigned int *) block_nums, size);

	/* Write to output buffer */
	for(uint16_t i = 0, j = 0; i < header.k; i++) {
		if(block_nums[i] == i)
			tmp = recon_arr[i];
		else if(j < found)
			tmp = out_arr[j++];

		if(tmp != NULL)
			memcpy(*output + i * size, tmp, size);
		tmp = NULL;
	}

	for(uint32_t i = 0; i < found; i++)
		free(out_arr[i]);
	return 0;
}

#ifdef BEF_CM256CC
/* Similar to the libfec interface in that we need to reconstruct the array to
 * its proper state. I should probably make a dedicated function to
 * reconstruction since it seems to pop up frequently...
 */
static int bef_decode_cm256(char **frags, uint32_t dummy, size_t frag_b,
			    char **output, size_t *onbyte,
			    struct bef_real_header header)
{
	int ret;
	uint32_t block_nums[header.k];
	char *recon_arr[header.k];
	bef_cm256_encoder_params params = {header.k, header.m,
					frag_b - sizeof(struct bef_fec_header)};
	bef_cm256_block blocks[header.k];
	*onbyte = (uint64_t) params.BlockBytes * header.k;
	*output = bef_malloc(*onbyte);

	bef_decode_reconstruct(frags, header.k, recon_arr, block_nums,
			       (uint32_t) header.k, header.m,
			       BEF_RECON_REPLACE);

	for(uint16_t i = 0; i < header.k; i++) {
		blocks[i].Block = recon_arr[i];
		blocks[i].Index = (unsigned char) block_nums[i];
	}

	ret = bef_cm256_decode(params, blocks);
	if(ret != 0) {
		bef_decode_free(*output);
		return -BEF_ERR_CM256;
	}

	/* Copy over our results */
	for(uint16_t i = 0; i < header.k; i++)
		memcpy(*output + i * params.BlockBytes, blocks[i].Block,
		       params.BlockBytes);
	return ret;
}
#endif

#ifdef BEF_OPENFEC
/* Like the others, we must reconstruct the given fragments into a more suitable
 * array. However, openfec wants each missing fragment to be NULL and to have as
 * many fragments as possible. So we try our best to provide that.
 */
static int bef_decode_openfec(char **frags, uint32_t frag_len, size_t frag_b,
			      char **output, size_t *onbyte,
			      struct bef_real_header header)
{
	int ret;
	of_status_t oret;
	of_session_t *session = NULL;
	uint32_t block_nums[header.k+header.m];
	char *recon_arr[header.k+header.m];
	char *source_tbl[header.k];
	size_t size = frag_b - sizeof(struct bef_fec_header);
	*onbyte = size * header.k;

	ret = bef_openfec_init(&session, header.k, header.m, size);
	if(ret != 0)
		return ret;

	bef_decode_reconstruct(frags, frag_len, recon_arr, block_nums,
			       (uint32_t) header.k, header.m, BEF_RECON_NULL);

	oret = of_set_available_symbols(session, (void **) recon_arr);
	if(oret != OF_STATUS_OK)
		return -BEF_ERR_OPENFEC;

	oret = of_finish_decoding(session);
	if(oret != OF_STATUS_OK)
		return -BEF_ERR_OPENFEC;

	oret = of_get_source_symbols_tab(session, (void **) source_tbl);
	if(oret != OF_STATUS_OK)
		return -BEF_ERR_OPENFEC;

	/* Set the source table to point at our output buffer */
	*output = bef_malloc(*onbyte);
	for(uint16_t i = 0; i < header.k; i++)
		memcpy(*output + i * size, source_tbl[i], size);

	/* free the allocated buffer */
	for(uint16_t i = 0; i < header.k; i++)
		if(block_nums[i] == UINT32_MAX)
			free(source_tbl[i]);

	/* Free our context */
	bef_openfec_destroy(session);

	return 0;
}
#endif

#ifdef BEF_LEOPARD
static int bef_decode_leopard(char **frags, uint32_t frag_len, size_t frag_b,
			      char **output, size_t *onbyte,
			      struct bef_real_header header)
{
	int ret = 0;
	LeopardResult res;
	uint32_t work_count;
	char **work_data;
	char **recon_arr;
	uint32_t *block_nums;
	uint64_t size = frag_b - sizeof(struct bef_fec_header);

	recon_arr = bef_malloc((header.k + header.m) * sizeof(*recon_arr));
	block_nums = bef_malloc((header.k + header.m) * sizeof(*block_nums));
	*onbyte = size * header.k;
	*output = bef_malloc(*onbyte);
	work_count = leo_decode_work_count(header.k, header.m);
	work_data = bef_malloc(work_count * sizeof(*work_data));

	for(uint32_t i = 0; i < work_count; i++)
		*(work_data + i) = bef_malloc(size);

	bef_decode_reconstruct(frags, frag_len, recon_arr, block_nums,
			       (uint32_t) header.k, header.m, BEF_RECON_NULL);

	res = leo_decode(size, header.k, header.m, work_count,
			 recon_arr, recon_arr + header.k, (void **) work_data);
	if(res == Leopard_Success) {
		for(uint16_t i = 0; i < header.k; i++) {
			if(*(recon_arr + i) == NULL)
				memcpy(*output + i * size, *(work_data + i),
				       size);
			else
				memcpy(*output + i * size, *(recon_arr + i),
				       size);
		}
	} else {
		bef_decode_free(*output);
		ret = -BEF_ERR_LEOPARD;
	}

	for(uint32_t i = 0; i < work_count; i++)
		free(*(work_data + i));
	free(work_data);

	free(recon_arr);
	free(block_nums);
	return ret;
}
#endif

#ifdef BEF_WIREHAIR
/* Unlike some of the others, like Leopard, OpenFEC, CM256, and zfec, we don't
 * actually need to reconstruct our array here. Instead, we just pass all the
 * blocks we have into the decoder.
 */
static int bef_decode_wirehair(char **frags, uint32_t frag_len, size_t frag_b,
			      char **output, size_t *onbyte,
			      struct bef_real_header header)
{
	WirehairResult res = Wirehair_NeedMore;
	WirehairCodec codec = NULL;
	struct bef_fec_header frag_h;
	size_t size = frag_b - sizeof(frag_h);
	*onbyte = size * header.k;

	codec = wirehair_decoder_create(0, *onbyte, size);
	if(codec == NULL)
		return -BEF_ERR_WIREHAIR;

	for(uint32_t i = 0; i < frag_len && res == Wirehair_NeedMore; i++) {
		memcpy(&frag_h, *(frags + i), sizeof(frag_h));

		res = wirehair_decode(codec,frag_h.block_num,
				      *(frags + i) + sizeof(frag_h),
				      frag_h.nbyte);
		if(res != Wirehair_Success && res != Wirehair_NeedMore) {
			wirehair_free(codec);
			return -BEF_ERR_WIREHAIR;
		}
	}

	*output = bef_malloc(*onbyte);
	res = wirehair_recover(codec, *output, *onbyte);
	if(res != Wirehair_Success) {
		bef_decode_free(*output);
		wirehair_free(codec);
		return -BEF_ERR_WIREHAIR;
	}

	wirehair_free(codec);
	return 0;
}
#endif

static int bef_sky_par(bef_par_t par_t, void *p, uint8_t flag)
{
	int ret = 0;
	void **pp = (void **) p;
	uint32_t *max = (uint32_t *) p;
	struct bef_real_header *header = (struct bef_real_header *) p;

	if(flag >= BEF_SPAR_MAXNUM)
		return -BEF_ERR_INVALINPUT;

	switch(par_t) {
#ifdef BEF_LIBERASURECODE
	case BEF_PAR_J_V_RS:
	case BEF_PAR_J_C_RS:
	case BEF_PAR_LE_V_RS:
	case BEF_PAR_I_V_RS:
	case BEF_PAR_I_C_RS:
		if(flag == BEF_SPAR_ENCODE) {
			*pp = &bef_encode_liberasurecode;
		} else if(flag == BEF_SPAR_DECODE) {
			*pp = &bef_decode_liberasurecode;
		} else if(flag == BEF_SPAR_MAXFRA) {
			if(par_t == BEF_PAR_J_C_RS)
				*max = 16;
			else
				*max = 32;
		} else if(flag == BEF_SPAR_INIT) {
			ret = bef_liberasurecode_init(header->par_t,
						      header->k,
						      header->m);
		} else if(flag == BEF_SPAR_DESTRO) {
			ret = bef_liberasurecode_destroy();
		} else if(flag == BEF_SPAR_MULTIT) {
			if(par_t == BEF_PAR_J_V_RS || par_t == BEF_PAR_J_C_RS)
				ret = 1;
		}
		break;
#endif
	case 0:
	case BEF_PAR_F_V_RS:
		if(flag == BEF_SPAR_ENCODE)
			*pp = &bef_encode_libfec;
		else if(flag == BEF_SPAR_DECODE)
			*pp = &bef_decode_libfec;
		else if(flag == BEF_SPAR_MAXFRA)
			*max = 256;
		else if(flag == BEF_SPAR_INIT)
			bef_fec_init(header->k, header->m);
		else if(flag == BEF_SPAR_DESTRO)
			bef_fec_destroy();
		break;
#ifdef BEF_CM256CC
	case BEF_PAR_CM_C_RS:
		if(flag == BEF_SPAR_ENCODE)
			*pp = &bef_encode_cm256;
		else if(flag == BEF_SPAR_DECODE)
			*pp = &bef_decode_cm256;
		else if(flag == BEF_SPAR_MAXFRA)
			*max = 256;
		break;
#endif
#ifdef BEF_OPENFEC
	case BEF_PAR_OF_V_RS:
		if(flag == BEF_SPAR_ENCODE)
			*pp = &bef_encode_openfec;
		else if(flag == BEF_SPAR_DECODE)
			*pp = &bef_decode_openfec;
		else if(flag == BEF_SPAR_MAXFRA)
			*max = 256;
		else if(flag == BEF_SPAR_MULTIT)
			ret = 1;
		break;
#endif
#ifdef BEF_LEOPARD
	case BEF_PAR_L_F_RS:
		if(flag == BEF_SPAR_ENCODE)
			*pp = &bef_encode_leopard;
		else if(flag == BEF_SPAR_DECODE)
			*pp = &bef_decode_leopard;
		else if(flag == BEF_SPAR_MAXFRA)
			*max = 65535;
		else if(flag == BEF_SPAR_INIT)
			ret = bef_leopard_init();
		break;
#endif
#ifdef BEF_WIREHAIR
	case BEF_PAR_W_FC:
		if(flag == BEF_SPAR_ENCODE)
			*pp = &bef_encode_wirehair;
		else if(flag == BEF_SPAR_DECODE)
			*pp = &bef_decode_wirehair;
		else if(flag == BEF_SPAR_MAXFRA)
			*max = 64000 + 65535;
		else if(flag == BEF_SPAR_INIT)
			ret = bef_wirehair_init();
		break;
#endif
	default:
		ret = -BEF_ERR_INVALINPUT;
		break;
	}

	return ret;
}

/* Function to detect whether a given parity type supports multithreading
 * Returns 0 if it does
 */
static int bef_par_multi(bef_par_t par_t)
{
	return bef_sky_par(par_t, NULL, BEF_SPAR_MULTIT);
}

/* Function to initialize reusable global variables */
static int bef_init(struct bef_real_header header)
{
	int ret;

	ret = bef_sky_par(header.par_t, &header, BEF_SPAR_INIT);

	return ret;
}

/* Function to clean up global reusable variables */
static int bef_destroy(struct bef_real_header header)
{
	int ret;

	ret = bef_sky_par(header.par_t, &header, BEF_SPAR_DESTRO);

	return ret;
}

uint32_t bef_max_frag(bef_par_t par_t)
{
	uint32_t ret = 0;

	bef_sky_par(par_t, &ret, BEF_SPAR_MAXFRA);

	return ret;
}

int bef_encode_ecc(const char *input, size_t inbyte, char **data,
		   char **parity,  size_t *frag_len,
		   struct bef_real_header header)
{
	int ret = 0;
	int (*f)(const char *, size_t, char **, char **,
		 size_t *, struct bef_real_header header) = NULL;

	if(bef_vflag > 1)
		fprintf(stderr,
			"Encoding %zu bytes, k %d, m %d, parity type %u\n",
			inbyte, header.k, header.m, header.par_t);

	ret = bef_sky_par(header.par_t, &f, BEF_SPAR_ENCODE);
	if(ret != 0)
		return ret;

	ret = (*f)(input, inbyte, data, parity, frag_len, header);

	return ret;
}

void bef_encode_free(char **data, char **parity, uint16_t k, uint16_t m)
{
	for(uint16_t i = 0; i < k; i++)
		free(*(data + i));
	for(uint16_t i = 0; i < m; i++)
		free(*(parity + i));
}

int bef_decode_ecc(char **frags, uint32_t frag_len, size_t frag_b,
		   char **output, size_t *onbyte,
		   struct bef_real_header header)
{
	int ret = 0;
	int (*f)(char **, uint32_t, size_t, char **, size_t *,
		 struct bef_real_header header) = NULL;

	/* Not enough fragments */
	if(frag_len < header.k)
		return -BEF_ERR_NEEDMORE;
	else if(frag_len == 0)
		return -BEF_ERR_INVALINPUT;

	/* All our codes require at least one parity */
	if(header.m == 0)
		return -BEF_ERR_INVALINPUT;

	if(bef_vflag > 1)
		fprintf(stderr,
			"Decoding %zu bytes, k %d, m %d, parity type %u\n",
			frag_b * frag_len, header.k, header.m, header.par_t);

	ret = bef_sky_par(header.par_t, &f, BEF_SPAR_DECODE);
	if(ret != 0)
		return ret;

	ret = (*f)(frags, frag_len, frag_b, output, onbyte, header);

	return ret;
}

void bef_decode_free(char *output)
{
	free(output);
}

static int bef_construct_header(int input, char **ibuf, size_t *ibuf_s,
				uint64_t *bsize, size_t *lret,
				struct bef_header *header)
{
	int ret;
	ssize_t rret;
	uint16_t k = header->header.k;
	uint16_t m = header->header.m;
	char **data = bef_malloc(k * sizeof(*data));
	char **parity = bef_malloc(m * sizeof(*parity));
	size_t frag_len;
	uint64_t pbyte;

	/* Our lovely, sexy, beautiful magic number */
	memcpy(header->magic, bef_magic, 7);
	header->hash_t = header->header.hash_t;

	/* To get nbyte, which depends on the backend used, we are going to
	 * construct the first block twice (so I don't have to lug around a
	 * evil output buffer or worse, two char **s). I know, I know! It's evil
	 * and wrong, but unless you want like 4 fragments in total, it'll be
	 * fine!
	 */
	rret = bef_safe_rw(input, *ibuf, *ibuf_s, BEF_SAFE_READ);
	if(rret == -1 || rret == 0) {
		ret = -BEF_ERR_READERR;
		goto out;
	}

	/* When getting less data from read, minimize block size instead,
	 * only do this when minimize flag is enabled, as it decreases the burst
	 * error size but leads to a much smaller file
	 */
	if(rret < *bsize * header->header.il_n && bef_mflag != 0) {
		*bsize = rret / header->header.il_n;
		*ibuf_s = header->header.il_n * *bsize;
		*ibuf_s += bef_sky_padding(*ibuf_s, header->header.il_n,
					   header->header.k, *bsize);
		*ibuf = bef_realloc(*ibuf, *ibuf_s);
		if(bef_vflag)
			fprintf(stderr, "Minimizing block size to %lu\n",
				*bsize);
	}

	/* Pad out if necessary */
	pbyte = bef_sky_padding((size_t) rret, header->header.il_n,
				header->header.k, *bsize);
	memset(*ibuf + rret, '\0', pbyte);

	*lret = (size_t) rret;

	/* Set to size of one block */
	if(rret != *ibuf_s / header->header.il_n)
		rret = *ibuf_s / header->header.il_n;

	ret = bef_encode_ecc(*ibuf, rret, data, parity, &frag_len,
			     header->header);
	if(ret != 0)
		goto out;

	if(bef_rflag != 0 &&
	   header->header.nbyte != frag_len + sizeof(struct bef_frag_header)) {
		if(bef_vflag)
			fprintf(stderr,
				"ERROR: Given fragment size does not match! Expected %lu\n",
				frag_len + sizeof(struct bef_frag_header));
		ret = -BEF_ERR_INVALINPUT;
		goto out;
	}

	header->header.nbyte = (uint64_t) (frag_len + sizeof(struct bef_frag_header));
	if(bef_vflag && bef_rflag == 0)
		fprintf(stderr, "Setting fragment size to %lu\n",
			header->header.nbyte);

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
			      bef_hash_t hash_t, uint64_t pbyte,
			      uint64_t block_num)
{
	int ret;
	struct bef_frag_header header;
	size_t offset = 0;

	header.pbyte = pbyte;
	header.block_num = block_num;

	/* header hash not set yet */
	memset(header.h_hash, '\0', sizeof(header.h_hash));

	/* Set body hash */
	ret = bef_digest(body, frag_len, header.b_hash, hash_t);
	if(ret != 0)
		return ret;

	bef_prepare_frag_header(&header);

	/* Set header hash */
	ret = bef_digest((const char *) &header, sizeof(header), header.h_hash,
			 hash_t);
	if(ret != 0)
		return ret;

	memcpy(output, &header, sizeof(header));
	offset += sizeof(header);
	memcpy(output + offset, body, frag_len);

	return 0;
}

/* output MUST BE AT LEAST (k+m) * nbyte large,
 * also frag_len + sizeof(bef_header) MUST EQUAL nbyte!!!
 */
static int bef_construct_blocks(char *output, char ***blocks,
				size_t frag_len, uint64_t pbyte,
				uint64_t il_count,
				struct bef_real_header header)
{
	int ret;
	int flag = 0;
	size_t offset = 0;
	uint64_t block_num;

#ifdef _OPENMP
#pragma omp parallel for private(block_num, offset, ret) if(bef_par_multi(header.par_t) == 0)
#endif
	for(uint32_t i = 0; i < (uint32_t) header.k + header.m; i++) {
		if(flag != 0)
			continue; //Iterate until done

		offset = header.nbyte * header.il_n * i;
		block_num = il_count * header.il_n;

		for(uint16_t j = 0; j < header.il_n; j++) {
			ret = bef_construct_frag(output + offset, blocks[j][i],
						 frag_len, header.hash_t,
						 pbyte, block_num++);
			if(ret != 0)
				flag = ret;
			offset += (size_t) header.nbyte;
		}
	}

	return flag;
}

static void bef_construct_buffers(char ****blocks, uint32_t km, uint16_t il_n)
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
			     uint64_t bsize, uint64_t il_count,
			     struct bef_real_header header)
{
	int ret;
	int flag = 0;
	uint8_t block_stat[header.il_n];
	char ***blocks;
	char **frags;
	size_t frag_len = 0;
	size_t tmp_len = 0;
	uint64_t pbyte = bef_sky_padding(ibuf_s, header.il_n, header.k,
					 bsize);
	size_t fbyte = (ibuf_s + pbyte) / header.il_n;

	memset(ibuf + ibuf_s, '\0', pbyte);
	memset(block_stat, '\0', header.il_n);

	bef_construct_buffers(&blocks, (uint32_t) header.k + header.m,
			      header.il_n);

#ifdef _OPENMP
	if(bef_numT == 0)
		omp_set_num_threads(MIN(omp_get_num_procs(), header.il_n));
	else
		omp_set_num_threads(bef_numT);
#pragma omp parallel for private(ret, frags, tmp_len) if(bef_par_multi(header.par_t) == 0)
#endif
	for(uint16_t i = 0; i < header.il_n; i++) {
		if(flag != 0)
			continue; //Will just iterate until i is il_n

		frags = *(blocks + i);

		ret = bef_encode_ecc(ibuf + i * fbyte, fbyte, frags,
				     frags + header.k, &tmp_len, header);

#ifdef _OPENMP
#pragma omp critical
{
#endif
		if(ret != 0) {
			block_stat[i] = 0;
			flag = ret;
		} else {
			block_stat[i] = 1;
		}

		if(frag_len != tmp_len)
			frag_len = tmp_len;
#ifdef _OPENMP
}
#endif
	}

	if(flag != 0) {
		for(uint16_t i = 0; i < header.il_n; i++)
			if(block_stat[i])
				bef_encode_free(*(blocks + i),
						*(blocks + i) + header.k,
						header.k, header.m);
		ret = flag;
	} else {
		ret = bef_construct_blocks(obuf, blocks, frag_len, pbyte,
					   il_count, header);

		for(uint16_t i = 0; i < header.il_n; i++)
			bef_encode_free(*(blocks + i), *(blocks + i) + header.k,
					header.k, header.m);
	}

	bef_construct_free(blocks, header.il_n);
	return ret;
}

static int bef_construct_encode(int input, int output,
				char *ibuf, uint64_t bsize, size_t lret,
				struct bef_real_header header)
{
	int ret;
	ssize_t bret;
	size_t obuf_s = ((uint32_t) header.k + header.m) * header.nbyte * header.il_n;
	char *obuf = bef_malloc(obuf_s);
	size_t ibuf_s = header.il_n * bsize;
	uint64_t il_count = 0;
	ibuf_s += bef_sky_padding(ibuf_s, header.il_n, header.k, bsize);

	/* Redo very first few blocks, source still in input */
	ret = bef_encode_blocks(ibuf, lret, obuf, bsize, il_count++, header);
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

		ret = bef_encode_blocks(ibuf, bret, obuf, bsize, il_count++,
					header);
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
		  struct bef_real_header header)
{
	int ret;
	ssize_t bret;
	char *ibuf;
	size_t ibuf_s;
	struct bef_header head;
	size_t lret;

	if(bsize == 0) {
		bsize = BEF_BSIZE;
		if(bef_vflag)
			fprintf(stderr, "Setting block size to default %lu\n",
				bsize);
	}
	if(header.par_t == 0) {
		header.par_t = BEF_PAR_DEFAULT;
		if(bef_vflag)
			fprintf(stderr,
				"Setting parity type to default fec-vand\n");
	}
	if(header.hash_t == 0) {
		header.hash_t = BEF_HASH_DEFAULT;
		if(bef_vflag)
			fprintf(stderr,
				"Setting hash type to default xxhash\n");
	}
	if(header.k == 0) {
		header.k = BEF_K_DEFAULT;
		if(bef_vflag)
			fprintf(stderr, "Setting k to default %u\n", header.k);
	}
	if(header.m == 0) {
		header.m = BEF_M_DEFAULT;
		if(bef_vflag)
			fprintf(stderr, "Setting m to default %u\n", header.m);
	}
	if(header.il_n == 0) {
		header.il_n = BEF_IL_N_DEFAULT;
		if(bef_vflag)
			fprintf(stderr, "Setting il_n to default %u\n",
				header.il_n);
	}

	ret = bef_init(header);
	if(ret != 0)
		return ret;

	/* Estimate size of our shared input buffer, using bsize and k */
	ibuf_s = header.il_n * bsize;
	ibuf_s += bef_sky_padding(ibuf_s, header.il_n, header.k, bsize);
	ibuf = bef_malloc(ibuf_s);

	head.header = header;

	ret = bef_construct_header(input, &ibuf, &ibuf_s, &bsize, &lret,
				   &head);
	if(ret != 0)
		goto out;

	if(bef_rflag == 0) {
		/* Write our header to output */
		bret = bef_safe_rw(output, (char *) &head, sizeof(head),
				   BEF_SAFE_WRITE);
		if(bret != sizeof(head)) {
			ret = -BEF_ERR_WRITEERR;
			goto out;
		}
	}

	if(head.header.nbyte == 0) {
		ret = -BEF_ERR_INVALINPUT;
		if(bef_vflag)
			fprintf(stderr,
				"ERROR: fragment size must be greater than 0\n");
		goto out;
	}

	/* ibuf should be freed by this function, so no need to check */
	ret = bef_construct_encode(input, output, ibuf, bsize, lret,
				   head.header);
	if(ret != 0)
		goto out;

out:
	bef_destroy(header);
	return ret;
}

static int bef_verify_fragment(char *frag, uint64_t nbyte, bef_hash_t hash_t,
			       uint8_t flag)
{
	int ret;
	uint8_t hash[BEF_HASH_SIZE];
	uint8_t *target_hash;
	struct bef_frag_header header;

	/* Copy over our header */
	memcpy(&header, frag, sizeof(header));

	/* Get our hash */
	if(flag == BEF_VERIFY_FRAG_H) {
		/* Zero out the original hash */
		memset(frag + sizeof(header.block_num) + sizeof(header.pbyte),
		       '\0', sizeof(header.h_hash));
		target_hash = header.h_hash;

		ret = bef_digest(frag, sizeof(header), hash, hash_t);

		/* Put the original hash back */
		memcpy(frag + sizeof(header.block_num) + sizeof(header.pbyte),
		       header.h_hash, sizeof(header.h_hash));
	} else {
		target_hash = header.b_hash;

		ret = bef_digest(frag + sizeof(header), nbyte - sizeof(header),
				 hash, hash_t);
	}

	if(ret != 0)
		return ret;

	/* Compare our two hashes */
	if(memcmp(target_hash, hash, sizeof(hash)) != 0) {
		if(bef_vflag > 2)
			fprintf(stderr, "ERROR: fragment corrupted!\n");
		return -BEF_ERR_INVALHASH;
	} else
		return 0;
}

static void bef_deconstruct_buffers(char ****buf_arr, uint32_t km,
				    uint64_t nbyte, uint16_t il_n)
{
	*buf_arr = bef_malloc(il_n * sizeof(*(*buf_arr)));
	for(uint16_t i = 0; i < il_n; i++) {
		*(*buf_arr + i) = bef_malloc(km * sizeof(*(*(*buf_arr))));

		for(uint32_t j = 0; j < km; j++)
			*(*(*buf_arr + i) + j) = bef_malloc(nbyte);
	}
}

static void bef_deconstruct_free(char ***buf_arr, uint32_t km, uint16_t il_n)
{
	for(uint16_t i = 0; i < il_n; i++) {
		for(uint32_t j = 0; j < km; j++)
			free(*(*(buf_arr + i) + j));
		free(*(buf_arr + i));
	}
	free(buf_arr);
}

static int bef_deconstruct_header(int input, struct bef_real_header *header)
{
	int ret;
	ssize_t bret;
	struct bef_header head;
	uint8_t hash[BEF_HASH_SIZE];

	bret = bef_safe_rw(input, (char *) &head, sizeof(head), BEF_SAFE_READ);
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
			if(bef_vflag)
				fprintf(stderr, "ERROR: Header corrupted!\n");
			return -BEF_ERR_INVALHEAD; //How sad!
		} else
			*header = head.header_b;
	} else
		*header = head.header;

	bef_unprepare_header(header); //Gotta get right endianness

	return 0;
}

/* Assumes we won't reach end of buffer exhausting sbyte, giving bad input where
 * we can't will lead to a buffer overflow
 */
static int bef_scan_fragment(char *ibuf, size_t *offset, size_t sbyte,
			     uint8_t flag, struct bef_real_header header)
{
	int ret;

	/* First test current offset, as this may be a well-crafted file */
	ret = bef_verify_fragment(ibuf + *offset, header.nbyte, header.hash_t,
				  BEF_VERIFY_FRAG_H);
	if(ret == 0)
		return 0;

	if(flag == BEF_SCAN_BACKWARDS) {
		*offset -= sbyte;
		sbyte *= 2;
	}

	for(; sbyte > 0; sbyte--) {
		ret = bef_verify_fragment(ibuf + *offset, header.nbyte,
					  header.hash_t, BEF_VERIFY_FRAG_H);
		if(ret == 0)
			return 0;

		*offset += 1;
	}

	if(bef_vflag > 1)
		fprintf(stderr,
			"ERROR: fragment not found within scan distance\n");

	return -BEF_ERR_NEEDMORE;
}

static int bef_deconstruct_fragments(char *ibuf, size_t ibuf_s,
				     char ***buf_arr, uint32_t *index,
				     uint64_t *pbyte, size_t *ahead,
				     uint64_t il_count, uint64_t sbyte,
				     struct bef_real_header header)
{
	int ret;
	uint16_t i;
	uint8_t flag = BEF_SCAN_FORWARDS;
	struct bef_frag_header frag_h;
	size_t offset = 0;
	memset(index, '\0', header.il_n * sizeof(*index));

	for(; offset < ibuf_s - (sbyte + header.nbyte);
	    offset += header.nbyte) {
		ret = bef_scan_fragment(ibuf, &offset, sbyte, flag, header);
		if(ret != 0) {
			flag = BEF_SCAN_BACKWARDS;
			continue; //Keep on searching
		}

		memcpy(&frag_h, ibuf + offset, sizeof(frag_h));
		bef_unprepare_frag_header(&frag_h);

		/* Check if it's outside our range, and if so break out of the
		 * loop
		 */
		if(frag_h.block_num >= il_count * header.il_n ||
		   frag_h.block_num < il_count * header.il_n - header.il_n)
			break;

		if(frag_h.pbyte > 0 && *pbyte == 0)
			*pbyte = frag_h.pbyte;

		ret = bef_verify_fragment(ibuf + offset, header.nbyte,
					  header.hash_t, BEF_VERIFY_FRAG_B);
		if(ret != 0) {
			flag = BEF_SCAN_BACKWARDS;
		} else {
			flag = BEF_SCAN_FORWARDS;
			i = frag_h.block_num % header.il_n;

			if(index[i] < (uint32_t) header.k + header.m) {
				memcpy(*(*(buf_arr + i) + index[i]),
				       ibuf + offset + sizeof(frag_h),
				       header.nbyte - sizeof(frag_h));
				index[i] += 1;
			}
		}
	}

	*ahead = ibuf_s - offset;

	/* If any has less than k good fragments, return with NEEDMORE */
	for(i = 0; i < header.il_n; i++) {
		if(index[i] < header.k) {
			if(bef_vflag)
				fprintf(stderr, "ERROR: Block %lu does not have k (%u) intact fragments",
					il_count * header.il_n - header.il_n + i,
					header.k);

			return -BEF_ERR_NEEDMORE;
		}
	}

	return 0;
}

static int bef_deconstruct_blocks(char *ibuf, size_t ibuf_s,
				  char **obuf, size_t *obuf_s,
				  uint64_t *pbyte, size_t *ahead,
				  uint64_t il_count, uint64_t sbyte,
				  struct bef_real_header header)
{
	int ret;
	int flag = 0;
	char *output;
	size_t onbyte;
	char ***buf_arr;
	uint32_t index[header.il_n];
	struct bef_frag_header frag_h;
	uint64_t frag_b = header.nbyte - sizeof(frag_h);

	if(frag_b > header.nbyte)
		return -BEF_ERR_OVERFLOW;

	bef_deconstruct_buffers(&buf_arr, (uint32_t) header.k + header.m,
				frag_b, header.il_n);

	ret = bef_deconstruct_fragments(ibuf, ibuf_s, buf_arr, index,
					pbyte, ahead, il_count, sbyte, header);
	if(ret != 0)
		goto out;

#ifdef _OPENMP
	if(bef_numT == 0)
		omp_set_num_threads(MIN(omp_get_num_procs(), header.il_n));
	else
		omp_set_num_threads(bef_numT);
#pragma omp parallel for private(output, onbyte, ret) if(bef_par_multi(header.par_t) == 0)
#endif
	for(uint16_t i = 0; i < header.il_n; i++) {
		if(flag != 0)
			continue; //Iterate until done

		ret = bef_decode_ecc(*(buf_arr + i), index[i],
				     frag_b, &output, &onbyte, header);
#ifdef _OPENMP
#pragma omp critical
{
#endif
		if(ret != 0)
			flag = ret;
		else {
			/* Allocate our output buffer */
			if(*obuf_s == 0) {
				*obuf_s = header.il_n * onbyte;
				*obuf = bef_malloc(*obuf_s);
			}

			/* Copy over the results to real output buffer */
			memcpy(*obuf + i * onbyte, output, onbyte);

			bef_decode_free(output);
		}
#ifdef _OPENMP
}
#endif
	}

	if(flag != 0)
		ret = flag;
out:
	bef_deconstruct_free(buf_arr, (uint32_t) header.k + header.m,
			     header.il_n);
	return ret;
}

/* Surprisingly _still_ simpler than encoding, I expected it to get a lot more
 * complicated accounting for deletions.
 */
int bef_deconstruct(int input, int output, struct bef_real_header header,
		    size_t sbyte)
{
	int ret = 0;
	ssize_t bret;
	char *ibuf = NULL;
	char *obuf = NULL;
	size_t ibuf_s;
	size_t obuf_s = 0; //Not known yet
	uint64_t pbyte = 0;
	size_t ahead = 0; //Number of bytes read ahead, when scanning.
	uint64_t il_count = 1; //Number of interleaved sets we've gone through

	if(bef_rflag == 0) {
		/* Get our header and verify its sanity */
		ret = bef_deconstruct_header(input, &header);
		if(ret != 0)
			return -BEF_ERR_INVALINPUT;

		if(header.k == 0) {
			if(bef_vflag)
				fprintf(stderr,
					"ERROR: Invalid k value in header\n");
			return -BEF_ERR_INVALINPUT;
		}
		if(header.nbyte == 0) {
			if(bef_vflag)
				fprintf(stderr,
					"ERROR: Invalid fragment size in header\n");
			return -BEF_ERR_INVALINPUT;
		}
		if(header.il_n == 0) {
			if(bef_vflag)
				fprintf(stderr,
					"ERROR: Invalid il_n value in header\n");
			return -BEF_ERR_INVALINPUT;
		}
		if(header.m == 0) {
			if(bef_vflag)
				fprintf(stderr,
					"ERROR: Invalid m value in header\n");
			return -BEF_ERR_INVALINPUT;
		}
		if(header.par_t == 0) {
			if(bef_vflag)
				fprintf(stderr,
					"ERROR: Invalid parity type in header\n");
			return -BEF_ERR_INVALINPUT;
		}
		if(header.hash_t == 0) {
			if(bef_vflag)
				fprintf(stderr,
					"ERROR: Invalid hash type in header\n");
			return -BEF_ERR_INVALINPUT;
		}
	} else {
		if(header.k == 0) {
			header.k = BEF_K_DEFAULT;
			if(bef_vflag)
				fprintf(stderr,
					"Setting k to default value %u\n",
					header.k);
		}
		if(header.m == 0) {
			header.m = BEF_M_DEFAULT;
			if(bef_vflag)
				fprintf(stderr,
					"Setting m to default value %u\n",
					header.m);
		}
		if(header.il_n == 0) {
			header.il_n = BEF_IL_N_DEFAULT;
			if(bef_vflag)
				fprintf(stderr,
					"Setting il_n to default value %u\n",
					header.il_n);
		}
		if(header.par_t == 0) {
			header.par_t = BEF_PAR_DEFAULT;
			if(bef_vflag)
				fprintf(stderr,
					"Setting parity type to default fec-vand\n");
		}
		if(header.hash_t == 0) {
			header.hash_t = BEF_HASH_DEFAULT;
			if(bef_vflag)
				fprintf(stderr,
					"Setting hash type to default xxhash\n");
		}
		if(header.nbyte == 0) {
			if(bef_vflag)
				fprintf(stderr,
					"ERROR: fragment size must be greater than 0\n");
			return -BEF_ERR_INVALINPUT;
		}
	}

	ret = bef_init(header);
	if(ret != 0)
		return ret;

	if(sbyte == 0) {
		sbyte = header.nbyte / 2;
		if(bef_vflag)
			fprintf(stderr, "Setting sbyte to default value %lu (half of fragment size)\n",
				sbyte);
	}

	sbyte *= (size_t) header.il_n * ((uint32_t) header.k + header.m);

	if(header.nbyte >=
	   (UINT64_MAX - sbyte) / (((uint32_t) header.k + header.m) * header.il_n))
		return -BEF_ERR_INVALINPUT;

	/* Allocate our buffers */
	ibuf_s = ((uint32_t) header.k + header.m) * header.nbyte * header.il_n;
	/* Allocate extra for scanning, plus align it with fragment size */
	if(sbyte >= header.nbyte)
		ibuf_s += sbyte;
	else
		ibuf_s += header.nbyte;
	ibuf_s = (ibuf_s / header.nbyte) * header.nbyte;
	sbyte /= (size_t) header.il_n * ((uint32_t) header.k + header.m);
	ibuf = bef_malloc(ibuf_s);

	/* Another eternal read loop incoming */
	while(1) {
		bret = bef_safe_rw(input, ibuf + ahead,
				   ibuf_s - ahead, BEF_SAFE_READ);
		if(bret == 0) {
			break; //Read it all folks!
		} else if(bret == -1) {
			ret = -BEF_ERR_READERR;
			goto out;
		}

		ret = bef_deconstruct_blocks(ibuf, ibuf_s, &obuf, &obuf_s,
					     &pbyte, &ahead, il_count, sbyte,
					     header);
		if(ret != 0)
			goto out;

		/* Check for integer overflow */
		if(obuf_s - pbyte > obuf_s){//Impossible, unless overflowed
			ret = -BEF_ERR_OVERFLOW;
			if(bef_vflag)
				fprintf(stderr,
					"ERROR: padded bytes overflowed\n");
			goto out;
		}

		bret = bef_safe_rw(output, obuf, obuf_s - pbyte,
				   BEF_SAFE_WRITE);
		if(bret != obuf_s - pbyte) {
			ret = -BEF_ERR_WRITEERR;
			goto out;
		}

		/* Copy over input that was read ahead */
		if(ahead > 0)
			memcpy(ibuf, ibuf + ibuf_s - ahead, ahead);

		il_count++;
	}

out:
	bef_destroy(header);
	free(obuf);
	free(ibuf);
	return ret;
}

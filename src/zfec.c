/* SPDX-License-Identifier: GPL-3.0-or-later */
/* personally modified libfec stolen from zfec, copyright shared with them
 * Copyright (C) 2007-2010 Zooko Wilcox-O'Hearn
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

#include "zfec.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#if defined __SSE3__ || __AVX2__
#include <immintrin.h>
#endif

/*
 * Primitive polynomials - see Lin & Costello, Appendix A,
 * and  Lee & Messerschmitt, p. 453.
 */
static const char*const Pp="101110001";


/*
 * To speed up computations, we have tables for logarithm, exponent and
 * inverse of a number.  We use a table for multiplication as well (it takes
 * 64K, no big deal even on a PDA, especially because it can be
 * pre-initialized an put into a ROM!), otherwhise we use a table of
 * logarithms. In any case the macro gf_mul(x,y) takes care of
 * multiplications.
 */

static gf gf_exp[510];  /* index->poly form conversion table    */
static int gf_log[256]; /* Poly->index form conversion table    */
static gf inverse[256]; /* inverse of field elem.               */
                                /* inv[\alpha**i]=\alpha**(GF_SIZE-i-1) */

/*
 * modnn(x) computes x % GF_SIZE, where GF_SIZE is 2**GF_BITS - 1,
 * without a slow divide.
 */
static gf
modnn(int x) {
    while (x >= 255) {
        x -= 255;
        x = (x >> 8) + (x & 255);
    }
    return x;
}

#define SWAP(a,b,t) {t tmp; tmp=a; a=b; b=tmp;}

/*
 * gf_mul(x,y) multiplies two numbers.  It is much faster to use a
 * multiplication table.
 */
static gf gf_mul_table[256][256];

#define gf_mul(x,y) gf_mul_table[x][y]

/*
 * Generate GF(2**m) from the irreducible polynomial p(X) in p[0]..p[m]
 * Lookup tables:
 *     index->polynomial form		gf_exp[] contains j= \alpha^i;
 *     polynomial form -> index form	gf_log[ j = \alpha^i ] = i
 * \alpha=x is the primitive element of GF(2^m)
 *
 * For efficiency, gf_exp[] has size 2*GF_SIZE, so that a simple
 * multiplication of two numbers can be resolved without calling modnn
 */
static void
_init_mul_table(void) {
  int i, j;
  for (i = 0; i < 256; i++)
      for (j = 0; j < 256; j++)
          gf_mul_table[i][j] = gf_exp[modnn (gf_log[i] + gf_log[j])];

  for (j = 0; j < 256; j++)
      gf_mul_table[0][j] = gf_mul_table[j][0] = 0;
}

#define NEW_GF_MATRIX(rows, cols) \
    (gf*)malloc(rows * cols)

/*
 * initialize the data structures used for computations in GF.
 */
static void
generate_gf (void) {
    int i;
    gf mask;

    mask = 1;                     /* x ** 0 = 1 */
    gf_exp[8] = 0;          /* will be updated at the end of the 1st loop */
    /*
     * first, generate the (polynomial representation of) powers of \alpha,
     * which are stored in gf_exp[i] = \alpha ** i .
     * At the same time build gf_log[gf_exp[i]] = i .
     * The first 8 powers are simply bits shifted to the left.
     */
    for (i = 0; i < 8; i++, mask <<= 1) {
        gf_exp[i] = mask;
        gf_log[gf_exp[i]] = i;
        /*
         * If Pp[i] == 1 then \alpha ** i occurs in poly-repr
         * gf_exp[8] = \alpha ** 8
         */
        if (Pp[i] == '1')
            gf_exp[8] ^= mask;
    }
    /*
     * now gf_exp[8] = \alpha ** 8 is complete, so can also
     * compute its inverse.
     */
    gf_log[gf_exp[8]] = 8;
    /*
     * Poly-repr of \alpha ** (i+1) is given by poly-repr of
     * \alpha ** i shifted left one-bit and accounting for any
     * \alpha ** 8 term that may occur when poly-repr of
     * \alpha ** i is shifted.
     */
    mask = 1 << 7;
    for (i = 9; i < 255; i++) {
        if (gf_exp[i - 1] >= mask)
            gf_exp[i] = gf_exp[8] ^ ((gf_exp[i - 1] ^ mask) << 1);
        else
            gf_exp[i] = gf_exp[i - 1] << 1;
        gf_log[gf_exp[i]] = i;
    }
    /*
     * log(0) is not defined, so use a special value
     */
    gf_log[0] = 255;
    /* set the extended gf_exp values for fast multiply */
    for (i = 0; i < 255; i++)
        gf_exp[i + 255] = gf_exp[i];

    /*
     * again special cases. 0 has no inverse. This used to
     * be initialized to 255, but it should make no difference
     * since noone is supposed to read from here.
     */
    inverse[0] = 0;
    inverse[1] = 1;
    for (i = 2; i <= 255; i++)
        inverse[i] = gf_exp[255 - gf_log[i]];
}

/*
 * Various linear algebra operations that i use often.
 */

/*
 * addmul() computes dst[] = dst[] + c * src[]
 * This is used often, so better optimize it! Currently the loop is
 * unrolled 16 times, a good value for 486 and pentium-class machines.
 * The case c=0 is also optimized, whereas c=1 is not. These
 * calls are unfrequent in my typical apps so I did not bother.
 */
#define addmul(dst, src, c, sz)                 \
    if (c != 0) _addmul1(dst, src, c, sz)

/* Table lookup method described by https://www.ssrc.ucsc.edu/media/pubs/c9a735170a7e1aa648b261ec6ad615e34af566db.pdf
 * Modified AVX2 version does the same, but with duplicated halves for double
 * the throughput
 */
#if defined __AVX2__
#define SIZE 32
static void
_addmul1(register gf*restrict dst, const register gf*restrict src, gf c, size_t sz) {
    register gf *gf_mulc = gf_mul_table[c];
    const gf* lim = &dst[sz - SIZE + 1];
    __m256i dst_mm, src_mm, t1_mm, t2_mm, mask1, mask2, l, h;
    t1_mm = _mm256_setr_epi8(gf_mulc[0x00], gf_mulc[0x01],
			     gf_mulc[0x02], gf_mulc[0x03],
			     gf_mulc[0x04], gf_mulc[0x05],
			     gf_mulc[0x06], gf_mulc[0x07],
			     gf_mulc[0x08], gf_mulc[0x09],
			     gf_mulc[0x0A], gf_mulc[0x0B],
			     gf_mulc[0x0C], gf_mulc[0x0D],
			     gf_mulc[0x0E], gf_mulc[0x0F],
			     gf_mulc[0x00], gf_mulc[0x01],
			     gf_mulc[0x02], gf_mulc[0x03],
			     gf_mulc[0x04], gf_mulc[0x05],
			     gf_mulc[0x06], gf_mulc[0x07],
			     gf_mulc[0x08], gf_mulc[0x09],
			     gf_mulc[0x0A], gf_mulc[0x0B],
			     gf_mulc[0x0C], gf_mulc[0x0D],
			     gf_mulc[0x0E], gf_mulc[0x0F]);
    t2_mm = _mm256_setr_epi8(gf_mulc[0x00], gf_mulc[0x10],
			     gf_mulc[0x20], gf_mulc[0x30],
			     gf_mulc[0x40], gf_mulc[0x50],
			     gf_mulc[0x60], gf_mulc[0x70],
			     gf_mulc[0x80], gf_mulc[0x90],
			     gf_mulc[0xA0], gf_mulc[0xB0],
			     gf_mulc[0xC0], gf_mulc[0xD0],
			     gf_mulc[0xE0], gf_mulc[0xF0],
			     gf_mulc[0x00], gf_mulc[0x10],
			     gf_mulc[0x20], gf_mulc[0x30],
			     gf_mulc[0x40], gf_mulc[0x50],
			     gf_mulc[0x60], gf_mulc[0x70],
			     gf_mulc[0x80], gf_mulc[0x90],
			     gf_mulc[0xA0], gf_mulc[0xB0],
			     gf_mulc[0xC0], gf_mulc[0xD0],
			     gf_mulc[0xE0], gf_mulc[0xF0]);
    mask1 = _mm256_set1_epi8(0x0F);
    mask2 = _mm256_set1_epi8(0xF0);

    for (; dst < lim; dst += SIZE, src += SIZE) {
        src_mm = _mm256_loadu_si256((__m256i *) src);
	l = _mm256_and_si256(src_mm, mask1);
	l = _mm256_shuffle_epi8(t1_mm, l);
	h = _mm256_and_si256(src_mm, mask2);
	h = _mm256_srli_epi64(h, 4);
	h = _mm256_shuffle_epi8(t2_mm, h);
	src_mm = _mm256_xor_si256(h, l);

	dst_mm = _mm256_loadu_si256((__m256i *) dst);
	dst_mm = _mm256_xor_si256(dst_mm, src_mm);
	_mm256_storeu_si256((__m256i *) dst, dst_mm);
    }

    lim += SIZE - 1;
    for (; dst < lim; dst++, src++)       /* final components */
        *dst ^= gf_mulc[*src];
}
#elif defined __SSE3__
#define SIZE 16
static void
_addmul1(register gf*restrict dst, const register gf*restrict src, gf c, size_t sz) {
    register gf *gf_mulc = gf_mul_table[c];
    const gf* lim = &dst[sz - SIZE + 1];
    __m128i dst_mm, src_mm, t1_mm, t2_mm, mask1, mask2, l, h;
    t1_mm = _mm_setr_epi8(gf_mulc[0x00], gf_mulc[0x01],
			  gf_mulc[0x02], gf_mulc[0x03],
			  gf_mulc[0x04], gf_mulc[0x05],
			  gf_mulc[0x06], gf_mulc[0x07],
			  gf_mulc[0x08], gf_mulc[0x09],
			  gf_mulc[0x0A], gf_mulc[0x0B],
			  gf_mulc[0x0C], gf_mulc[0x0D],
			  gf_mulc[0x0E], gf_mulc[0x0F]);
    t2_mm = _mm_setr_epi8(gf_mulc[0x00], gf_mulc[0x10],
			  gf_mulc[0x20], gf_mulc[0x30],
			  gf_mulc[0x40], gf_mulc[0x50],
			  gf_mulc[0x60], gf_mulc[0x70],
			  gf_mulc[0x80], gf_mulc[0x90],
			  gf_mulc[0xA0], gf_mulc[0xB0],
			  gf_mulc[0xC0], gf_mulc[0xD0],
			  gf_mulc[0xE0], gf_mulc[0xF0]);
    mask1 = _mm_set1_epi8(0x0F);
    mask2 = _mm_set1_epi8(0xF0);

    for (; dst < lim; dst += SIZE, src += SIZE) {
        src_mm = _mm_loadu_si128((__m128i *) src);
	l = _mm_and_si128(src_mm, mask1);
	l = _mm_shuffle_epi8(t1_mm, l);
	h = _mm_and_si128(src_mm, mask2);
	h = _mm_srli_epi64(h, 4);
	h = _mm_shuffle_epi8(t2_mm, h);
	src_mm = _mm_xor_si128(h, l);

	dst_mm = _mm_loadu_si128((__m128i *) dst);
	dst_mm = _mm_xor_si128(dst_mm, src_mm);
	_mm_storeu_si128((__m128i *) dst, dst_mm);
    }

    lim += SIZE - 1;
    for (; dst < lim; dst++, src++)       /* final components */
        *dst ^= gf_mulc[*src];
}
#else
#define UNROLL 8
static void
_addmul1(register gf*restrict dst, const register gf*restrict src, gf c, size_t sz) {
    register gf *gf_mulc = gf_mul_table[c];
    const gf* lim = &dst[sz - UNROLL + 1];

    for (; dst < lim; dst += UNROLL, src += UNROLL) {
        dst[0] ^= gf_mulc[src[0]];
        dst[1] ^= gf_mulc[src[1]];
        dst[2] ^= gf_mulc[src[2]];
        dst[3] ^= gf_mulc[src[3]];
        dst[4] ^= gf_mulc[src[4]];
        dst[5] ^= gf_mulc[src[5]];
        dst[6] ^= gf_mulc[src[6]];
        dst[7] ^= gf_mulc[src[7]];
    }
    lim += UNROLL - 1;
    for (; dst < lim; dst++, src++)       /* final components */
        *dst ^= gf_mulc[*src];
}
#endif

/*
 * computes C = AB where A is n*k, B is k*m, C is n*m
 */
static void
_matmul(gf * a, gf * b, gf * c, unsigned n, unsigned k, unsigned m) {
    unsigned row, col, i;

    for (row = 0; row < n; row++) {
        for (col = 0; col < m; col++) {
            gf *pa = &a[row * k];
            gf *pb = &b[col];
            gf acc = 0;
            for (i = 0; i < k; i++, pa++, pb += m)
                acc ^= gf_mul (*pa, *pb);
            c[row * m + col] = acc;
        }
    }
}

/*
 * _invert_mat() takes a matrix and produces its inverse
 * k is the size of the matrix.
 * (Gauss-Jordan, adapted from Numerical Recipes in C)
 * Return non-zero if singular.
 */
static void
_invert_mat(gf* src, size_t k) {
    gf c;
    size_t irow = 0;
    size_t icol = 0;
    size_t row, col, i, ix;

    unsigned* indxc = (unsigned*) malloc (k * sizeof(unsigned));
    unsigned* indxr = (unsigned*) malloc (k * sizeof(unsigned));
    unsigned* ipiv = (unsigned*) malloc (k * sizeof(unsigned));
    gf *id_row = NEW_GF_MATRIX (1, k);

    memset (id_row, '\0', k * sizeof (gf));
    /*
     * ipiv marks elements already used as pivots.
     */
    for (i = 0; i < k; i++)
        ipiv[i] = 0;

    for (col = 0; col < k; col++) {
        gf *pivot_row;
        /*
         * Zeroing column 'col', look for a non-zero element.
         * First try on the diagonal, if it fails, look elsewhere.
         */
        if (ipiv[col] != 1 && src[col * k + col] != 0) {
            irow = col;
            icol = col;
            goto found_piv;
        }
        for (row = 0; row < k; row++) {
            if (ipiv[row] != 1) {
                for (ix = 0; ix < k; ix++) {
                    if (ipiv[ix] == 0) {
                        if (src[row * k + ix] != 0) {
                            irow = row;
                            icol = ix;
                            goto found_piv;
                        }
                    } else
                        assert (ipiv[ix] <= 1);
                }
            }
        }
      found_piv:
        ++(ipiv[icol]);
        /*
         * swap rows irow and icol, so afterwards the diagonal
         * element will be correct. Rarely done, not worth
         * optimizing.
         */
        if (irow != icol)
            for (ix = 0; ix < k; ix++)
                SWAP (src[irow * k + ix], src[icol * k + ix], gf);
        indxr[col] = irow;
        indxc[col] = icol;
        pivot_row = &src[icol * k];
        c = pivot_row[icol];
        assert (c != 0);
        if (c != 1) {                       /* otherwhise this is a NOP */
            /*
             * this is done often , but optimizing is not so
             * fruitful, at least in the obvious ways (unrolling)
             */
            c = inverse[c];
            pivot_row[icol] = 1;
            for (ix = 0; ix < k; ix++)
                pivot_row[ix] = gf_mul (c, pivot_row[ix]);
        }
        /*
         * from all rows, remove multiples of the selected row
         * to zero the relevant entry (in fact, the entry is not zero
         * because we know it must be zero).
         * (Here, if we know that the pivot_row is the identity,
         * we can optimize the addmul).
         */
        id_row[icol] = 1;
        if (memcmp (pivot_row, id_row, k * sizeof (gf)) != 0) {
            gf *p = src;
            for (ix = 0; ix < k; ix++, p += k) {
                if (ix != icol) {
                    c = p[icol];
                    p[icol] = 0;
                    addmul (p, pivot_row, c, k);
                }
            }
        }
        id_row[icol] = 0;
    }                           /* done all columns */
    for (col = k; col > 0; col--)
        if (indxr[col-1] != indxc[col-1])
            for (row = 0; row < k; row++)
                SWAP (src[row * k + indxr[col-1]], src[row * k + indxc[col-1]], gf);
    free(indxc);
    free(indxr);
    free(ipiv);
    free(id_row);
}

/*
 * fast code for inverting a vandermonde matrix.
 *
 * NOTE: It assumes that the matrix is not singular and _IS_ a vandermonde
 * matrix. Only uses the second column of the matrix, containing the p_i's.
 *
 * Algorithm borrowed from "Numerical recipes in C" -- sec.2.8, but largely
 * revised for my purposes.
 * p = coefficients of the matrix (p_i)
 * q = values of the polynomial (known)
 */
void
_invert_vdm (gf* src, unsigned k) {
    unsigned i, j, row, col;
    gf *b, *c, *p;
    gf t, xx;

    if (k == 1)                   /* degenerate case, matrix must be p^0 = 1 */
        return;
    /*
     * c holds the coefficient of P(x) = Prod (x - p_i), i=0..k-1
     * b holds the coefficient for the matrix inversion
     */
    c = NEW_GF_MATRIX (1, k);
    b = NEW_GF_MATRIX (1, k);

    p = NEW_GF_MATRIX (1, k);

    for (j = 1, i = 0; i < k; i++, j += k) {
        c[i] = 0;
        p[i] = src[j];            /* p[i] */
    }
    /*
     * construct coeffs. recursively. We know c[k] = 1 (implicit)
     * and start P_0 = x - p_0, then at each stage multiply by
     * x - p_i generating P_i = x P_{i-1} - p_i P_{i-1}
     * After k steps we are done.
     */
    c[k - 1] = p[0];              /* really -p(0), but x = -x in GF(2^m) */
    for (i = 1; i < k; i++) {
        gf p_i = p[i];            /* see above comment */
        for (j = k - 1 - (i - 1); j < k - 1; j++)
            c[j] ^= gf_mul (p_i, c[j + 1]);
        c[k - 1] ^= p_i;
    }

    for (row = 0; row < k; row++) {
        /*
         * synthetic division etc.
         */
        xx = p[row];
        t = 1;
        b[k - 1] = 1;             /* this is in fact c[k] */
        for (i = k - 1; i > 0; i--) {
            b[i-1] = c[i] ^ gf_mul (xx, b[i]);
            t = gf_mul (xx, t) ^ b[i-1];
        }
        for (col = 0; col < k; col++)
            src[col * k + row] = gf_mul (inverse[t], b[col]);
    }
    free (c);
    free (b);
    free (p);
    return;
}

/* There are few (if any) ordering guarantees that apply to reads and writes
 * of this static int across threads.  This is the reason for some of the
 * tight requirements for how `fec_init` is called.  If we could use a mutex
 * or a C11 atomic here we might be able to provide more flexibility to
 * callers.  It's tricky to do that while remaining compatible with all of
 * macOS/Linux/Windows and CPython's MSVC requirements and not switching to
 * C++ (or something even more different).
 */
static int fec_initialized = 0;

void
fec_init (void) {
    if (fec_initialized == 0) {
        generate_gf();
        _init_mul_table();
        fec_initialized = 1;
    }
}

/*
 * This section contains the proper FEC encoding/decoding routines.
 * The encoding matrix is computed starting with a Vandermonde matrix,
 * and then transforming it into a systematic matrix.
 */

#define FEC_MAGIC	0xFECC0DEC

void
fec_free (fec_t *p) {
    assert (p != NULL && p->magic == (((FEC_MAGIC ^ p->k) ^ p->n) ^ (unsigned long) (p->enc_matrix)));
    free (p->enc_matrix);
    free (p);
}

fec_t *
fec_new(unsigned short k, unsigned short n) {
    unsigned row, col;
    gf *p, *tmp_m;

    fec_t *retval;

    assert(k >= 1);
    assert(n >= 1);
    assert(n <= 256);
    assert(k <= n);

    if (fec_initialized == 0) {
        return NULL;
    }

    retval = (fec_t *) malloc (sizeof (fec_t));
    retval->k = k;
    retval->n = n;
    retval->enc_matrix = NEW_GF_MATRIX (n, k);
    retval->magic = ((FEC_MAGIC ^ k) ^ n) ^ (unsigned long) (retval->enc_matrix);
    tmp_m = NEW_GF_MATRIX (n, k);
    /*
     * fill the matrix with powers of field elements, starting from 0.
     * The first row is special, cannot be computed with exp. table.
     */
    tmp_m[0] = 1;
    for (col = 1; col < k; col++)
        tmp_m[col] = 0;
    for (p = tmp_m + k, row = 0; row + 1 < n; row++, p += k)
        for (col = 0; col < k; col++)
            p[col] = gf_exp[modnn (row * col)];

    /*
     * quick code to build systematic matrix: invert the top
     * k*k vandermonde matrix, multiply right the bottom n-k rows
     * by the inverse, and construct the identity matrix at the top.
     */
    _invert_vdm (tmp_m, k);        /* much faster than _invert_mat */
    _matmul(tmp_m + k * k, tmp_m, retval->enc_matrix + k * k, n - k, k, k);
    /*
     * the upper matrix is I so do not bother with a slow multiply
     */
    memset (retval->enc_matrix, '\0', k * k * sizeof (gf));
    for (p = retval->enc_matrix, col = 0; col < k; col++, p += k + 1)
        *p = 1;
    free (tmp_m);

    return retval;
}

/* To make sure that we stay within cache in the inner loops of fec_encode().  (It would
   probably help to also do this for fec_decode(). */
#ifndef STRIDE
#define STRIDE 8192
#endif

void
fec_encode(const fec_t* code, const gf*restrict const*restrict const src, gf*restrict const*restrict const fecs, const unsigned*restrict const block_nums, size_t num_block_nums, size_t sz) {
    unsigned char i, j;
    size_t k;
    unsigned fecnum;
    const gf* p;

    for (k = 0; k < sz; k += STRIDE) {
        size_t stride = ((sz-k) < STRIDE)?(sz-k):STRIDE;
        for (i=0; i<num_block_nums; i++) {
            fecnum=block_nums[i];
            assert (fecnum >= code->k);
            memset(fecs[i]+k, 0, stride);
            p = &(code->enc_matrix[fecnum * code->k]);
            for (j = 0; j < code->k; j++)
                addmul(fecs[i]+k, src[j]+k, p[j], stride);
        }
    }
}

/**
 * Build decode matrix into some memory space.
 *
 * @param matrix a space allocated for a k by k matrix
 */
void
build_decode_matrix_into_space(const fec_t*restrict const code, const unsigned*const restrict index, const unsigned k, gf*restrict const matrix) {
    unsigned short i;
    gf* p;
    for (i=0, p=matrix; i < k; i++, p += k) {
        if (index[i] < k) {
            memset(p, 0, k);
            p[i] = 1;
        } else {
            memcpy(p, &(code->enc_matrix[index[i] * code->k]), k);
        }
    }
    _invert_mat (matrix, k);
}

void
fec_decode(const fec_t* code, const gf*restrict const*restrict const inpkts, gf*restrict const*restrict const outpkts, const unsigned*restrict const index, size_t sz) {
    gf* m_dec = (gf*)alloca(code->k * code->k);

    /* char is large enough for outix - it counts the number of primary blocks
       we are decoding for return.  the most primary blocks we might have to
       decode is for k == 128, m == 256.  in this case we might be given 128
       secondary blocks and have to decode 128 primary blocks.  if k decreases
       then the number of total blocks we might have to return decreases.  if
       k increases then the number of secondary blocks that exist decreases so
       we will be passed some primary blocks and the number of primary blocks
       we have to decode decreases. */
    unsigned char outix=0;

    /* row and col are compared directly to k, which could be 256, so make
       them large enough to represent 256.
     */
    unsigned short row=0;
    unsigned short col=0;
    build_decode_matrix_into_space(code, index, code->k, m_dec);

    for (row=0; row<code->k; row++) {
        assert ((index[row] >= code->k) || (index[row] == row)); /* If the block whose number is i is present, then it is required to be in the i'th element. */
        if (index[row] >= code->k) {
            memset(outpkts[outix], 0, sz);
            for (col=0; col < code->k; col++)
                addmul(outpkts[outix], inpkts[col], m_dec[row * code->k + col], sz);
            outix++;
        }
    }
}

/*
 * This work is derived from the "fec" software by Luigi Rizzo, et al., the
 * copyright notice and licence terms of which are included below for reference.
 * fec.c -- forward error correction based on Vandermonde matrices 980624 (C)
 * 1997-98 Luigi Rizzo (luigi@iet.unipi.it)
 *
 * Portions derived from code by Phil Karn (karn@ka9q.ampr.org),
 * Robert Morelos-Zaragoza (robert@spectra.eng.hawaii.edu) and Hari
 * Thirumoorthy (harit@spectra.eng.hawaii.edu), Aug 1995
 *
 * Modifications by Dan Rubenstein (see Modifications.txt for
 * their description.
 * Modifications (C) 1998 Dan Rubenstein (drubenst@cs.umass.edu)
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above
 *    copyright notice, this list of conditions and the following
 *    disclaimer in the documentation and/or other materials
 *    provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
 * PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
 * OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA,
 * OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR
 * TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY
 * OF SUCH DAMAGE.
 */

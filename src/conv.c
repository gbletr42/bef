/* SPDX-License-Identifier: GPL-3.0-or-later */
/* bef (block erasure format) convolutional encoding library code, mostly copied
 * from libcorrect
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
#include "conv.h"

/* Bit abstraction structs */
struct bef_bit_io {
	uint8_t *buf;
	size_t len;

	uint8_t byte;
	uint8_t byte_len;

	uint8_t index;
	uint8_t padding[5];
};

static uint8_t reverse_table[256];

#ifndef __GNUC__
static inline int popcount(int x) {
	/* taken from the helpful http://graphics.stanford.edu/~seander/bithacks.html#CountBitsSetParallel */
	x = x - ((x >> 1) & 0x55555555);
	x = (x & 0x33333333) + ((x >> 2) & 0x33333333);
	return ((x + (x >> 4) & 0x0f0f0f0f) * 0x01010101) >> 24;
}
#else
#define popcount __builtin_popcount
#endif

/* This should be constructed globally if convolution is enabled */
void bef_construct_reverse_table() {
	for(uint16_t i = 0; i < 256; i++) {
		reverse_table[i] =	(i & 0x80) >> 7 | (i & 0x40) >> 5 |
					(i & 0x20) >> 3 | (i & 0x10) >> 1 |
					(i & 0x08) << 1 | (i & 0x04) << 3 |
					(i & 0x02) << 5 | (i & 0x01) << 7;
	}
}

static void bef_bit_io_configure(struct bef_bit_io *p, uint8_t *buf, size_t len,
				 uint8_t flag)
{
	p->buf = buf;
	p->len = len;

	if(flag == 0) {
		p->byte = *buf;
		p->byte_len = 8;
	} else {
		p->byte = 0;
		p->byte_len = 0;
	}
	p->index = 0;
}

static void bef_bit_write(struct bef_bit_io *p, uint8_t val, uint32_t n)
{
	for(uint32_t i = 0; i < n; i++) {
		p->byte |= val & 1;
		p->byte_len++;

		if(p->byte_len == 8) {
			/* 8 bits in a byte -- move to the next byte */
			p->buf[p->index++] = p->byte;
			p->byte = 0;
			p->byte_len = 0;
		} else {
			p->byte <<= 1;
		}
		val >>= 1;
	}
}

static void bef_bit_write_flush(struct bef_bit_io *p)
{
	if(p->byte_len != 0) {
		p->byte <<= (8 - p->byte_len);
		p->buf[p->index++] = p->byte;
		p->byte_len = 0;
	}
}

static uint8_t bef_bit_read(struct bef_bit_io *p, uint32_t n)
{
	uint32_t read = 0;
	uint32_t m = n;
	uint8_t mask = (1 << n) - 1;

	if(p->byte_len < n) {
		read = p->byte & ((1 << p->byte_len) - 1);
		p->index++;
		p->byte = p->buf[p->index];
		n -= p->byte_len;
		p->byte_len = 8;
		read <<= n;
	}

	mask <<= (p->byte_len - n);
	read |= (p->byte & mask) >> (p->byte_len - n);
	p->byte_len -= n;
	return reverse_table[read] >> (8 - m);
}

/* Good polynomials are available in conv.h */
static void bef_fill_table(uint8_t rate, uint8_t order, uint16_t *poly,
			   uint32_t *table)
{
	uint32_t out;
	uint32_t mask;

	for(uint32_t i = 0; i < 1 << order; i++) {
		out = 0;
		mask  = 1;
		for(size_t j = 0; j < rate; j++) {
			out |= (popcount(i & poly[j]) % 2) ? mask : 0;
			mask <<= 1;
		}
		table[i] = out;
	}
}

void bef_conv_tbl_init(uint8_t rate, uint8_t order, uint16_t *poly,
		       uint32_t **table)
{
	*table = malloc(sizeof(*(*table)) * (1 << order));
	bef_fill_table(rate, order, poly, *table);
}

size_t bef_conv_get_size(uint8_t rate, uint8_t order, size_t size)
{
	size_t out = rate * (size * 8 + order + 1);
	if(out % 8 != 0)
		return out / 8 + 1;
	else
		return out / 8;
}

/* obuf must be at least bef_conv_get_size() long and is assumed to be so.
 * returns the number of bytes written to obuf
 *
 * Comments copied from libcorrect, with formatting changes.
 */
void bef_conv_encode(char *ibuf, size_t ibuf_s, char *obuf,
		     uint8_t rate, uint8_t order, uint32_t *table)
{
	/* convolutional code convolves filter coefficients, given by
	 * the polynomial, with some history from our message.
	 * the history is stored as single subsequent bits in shiftregister
	 */
	uint32_t shiftregister = 0;
	/* shiftmask is the shiftregister bit mask that removes bits
	 * that extend beyond order
	 * e.g. if order is 7, then remove the 8th bit and beyond
	 */
	uint32_t shiftmask = (1 << order) - 1;
	size_t obuf_s = bef_conv_get_size(rate, order, ibuf_s);
	struct bef_bit_io writer;
	struct bef_bit_io reader;
	uint32_t out;

	bef_bit_io_configure(&writer, (uint8_t *) obuf, obuf_s, 1);
	bef_bit_io_configure(&reader, (uint8_t *) ibuf, ibuf_s, 0);

	for(size_t i = 0; i < 8 * ibuf_s; i++) {
		/* shiftregister has oldest bits on left, newest on right */
		shiftregister <<= 1;
		shiftregister |= bef_bit_read(&reader, 1);
		shiftregister &= shiftmask;
		/* shift most significant bit from byte and move down one bit at
		 * a time
		 */

		/* We do direct lookup of our convolutional output here
		 * all of the bits from this convolution are stored in this row
		 */
		out = table[shiftregister];
		bef_bit_write(&writer, out, rate);
	}

	/* now flush the shiftregister
	 * this is simply running the loop as above but without any new inputs
	 * or rather, the new input string is all 0s
	 */
	for(size_t i = 0; i < order + 1; i++) {
		shiftregister <<= 1;
		shiftregister &= shiftmask;
		out = table[shiftregister];
		bef_bit_write(&writer, out, rate);
	}

	/* 0-fill any remaining bits on our final byte */
	bef_bit_write_flush(&writer);
}

/*
 * Copyright (c) 2016, Brian Armstrong
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1.	Redistributions of source code must retain the above copyright notice,
 *	this list of conditions and the following disclaimer.
 *
 * 2.	Redistributions in binary form must reproduce the above copyright
 *	notice, this list of conditions and the following disclaimer in the
 *	documentation and/or other materials provided with the distribution.
 *
 * 3.	Neither the name of the copyright holder nor the names of its
 *	contributors may be used to endorse or promote products derived from
 *	this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

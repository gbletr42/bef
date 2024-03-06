/* SPDX-License-Identifier: GPL-3.0-or-later */
/* bef (block erasure format) convolutional library headers
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

#include <stdint.h>
#include <stdlib.h>

/* Good polynomials (from libcorrect) */
static const uint16_t correct_conv_r12_6_polynomial[] = {073, 061};
/* Default and recommended Voyager polynomials */
static const uint16_t correct_conv_r12_7_polynomial[] = {0161, 0127};
static const uint16_t correct_conv_r12_8_polynomial[] = {0225, 0373};
static const uint16_t correct_conv_r12_9_polynomial[] = {0767, 0545};
static const uint16_t correct_conv_r13_6_polynomial[] = {053, 075, 047};
static const uint16_t correct_conv_r13_7_polynomial[] = {0137, 0153, 0121};
static const uint16_t correct_conv_r13_8_polynomial[] = {0333, 0257, 0351};
static const uint16_t correct_conv_r13_9_polynomial[] = {0417, 0627, 0675};

/* Construct reverse table for convolution, should be called ideally once */
void bef_construct_reverse_table();

/* Initialize the table used for convolution, passed by caller */
void bef_conv_tbl_init(uint8_t rate, uint8_t order, uint16_t *poly,
		       uint32_t **table);

/* Returns the estimated size of an encoded stream, in bytes*/
size_t bef_conv_get_size(uint8_t rate, uint8_t order, size_t size);

/* Encodes a given stream to an obuf of at least bef_conv_get_size() bytes */
void bef_conv_encode(char *ibuf, size_t ibuf_s, char *obuf,
		     uint8_t rate, uint8_t order, uint32_t *table);


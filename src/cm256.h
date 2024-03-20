/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Header file for cm256cc C++ wrapper code
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

#ifndef BEF_CM256_H

/* Encoder parameters */
typedef struct cm256_encoder_params_t {
	/* Original block count < 256 */
	int OriginalCount;

        /* Recovery block count < 256 */
        int RecoveryCount;

        /* Number of bytes per block (all blocks are the same size in bytes) */
        int BlockBytes;
} bef_cm256_encoder_params;

/* Descriptor for data block */
typedef struct cm256_block_t {
        /* Pointer to data received. */
        void* Block;

        /* Block index.
         * For original data, it will be in the range
         *    [0..(originalCount-1)] inclusive.
         * For recovery data, the first one's Index must be originalCount,
         *    and it will be in the range
         *    [originalCount..(originalCount+recoveryCount-1)] inclusive.
	 */
        unsigned char Index;
        /* Ignored during encoding, required during decoding. */
} bef_cm256_block;

/*
 * Cauchy MDS GF(256) encode
 *
 * This produces a set of recovery blocks that should be transmitted after the
 * original data blocks.
 *
 * It takes in 'originalCount' equal-sized blocks and produces 'recoveryCount'
 * equally-sized recovery blocks.
 *
 * The input 'originals' array allows more natural usage of the library.
 * The output recovery blocks are stored end-to-end in 'recoveryBlocks'.
 * 'recoveryBlocks' should have recoveryCount * blockBytes bytes available.
 *
 * Precondition: originalCount + recoveryCount <= 256
 *
 * When transmitting the data, the block index of the data should be sent,
 * and the recovery block index is also needed.  The decoder should also
 * be provided with the values of originalCount, recoveryCount and blockBytes.
 *
 * Example wire format:
 * [originalCount(1 byte)] [recoveryCount(1 byte)]
 * [blockIndex(1 byte)] [blockData(blockBytes bytes)]
 *
 * Be careful not to mix blocks from different encoders.
 *
 * It is possible to support variable-length data by including the original
 * data length at the front of each message in 2 bytes, such that when it is
 * recovered after a loss the data length is available in the block data and
 * the remaining bytes of padding can be neglected.
 *
 * Returns 0 on success, and any other code indicates failure.
 */
int bef_cm256_encode(
		     /* Encoder parameters */
		     bef_cm256_encoder_params params,
		     /* Array of pointers to original blocks */
		     bef_cm256_block *originals,
		     /* Output recovery blocks end-to-end */
		     void *recoveryBlocks);

/*
 * Cauchy MDS GF(256) decode
 *
 * This recovers the original data from the recovery data in the provided
 * blocks.  There should be 'originalCount' blocks in the provided array.
 * Recovery will always be possible if that many blocks are received.
 *
 * Provide the same values for 'originalCount', 'recoveryCount', and
 * 'blockBytes' used by the encoder.
 *
 * The block Index should be set to the block index of the original data,
 * as described in the cm256_block struct comments above.
 *
 * Recovery blocks will be replaced with original data and the Index
 * will be updated to indicate the original block that was recovered.
 *
 * Returns 0 on success, and any other code indicates failure.
 */
int bef_cm256_decode(
		     /* Encoder parameters */
		     bef_cm256_encoder_params params,
		     /* Array of 'originalCount' blocks as described above */
		     bef_cm256_block *blocks);

#endif /* BEF_CM256_H */

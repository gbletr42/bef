/* SPDX-License-Identifier: GPL-3.0-or-later */
/* code for cm256cc wrapper functions, pretty thin wrapper all things considered
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
extern "C"
{
#include "bef.h"
#include "cm256.h"
}
#include <cm256cc/cm256.h>

static CM256 cm256;

extern "C" int bef_cm256_encode(bef_cm256_encoder_params params,
				bef_cm256_block *originals,
				void *recoveryBlocks)
{
	int ret;
	CM256::cm256_encoder_params p = {params.OriginalCount,
					 params.RecoveryCount,
					 params.BlockBytes};
	CM256::cm256_block *b = reinterpret_cast<CM256::cm256_block *>(bef_malloc(params.OriginalCount * sizeof(CM256::cm256_block)));

	for(int i = 0; i < params.OriginalCount; i++) {
		b[i].Block = originals[i].Block;
		b[i].Index = originals[i].Index;
	}

	if(! cm256.isInitialized()) {
		free(b);
		return -BEF_ERR_CM256;
	}

	ret = cm256.cm256_encode(p, b, recoveryBlocks);
	free(b);
	return ret;
}

extern "C" int bef_cm256_decode(bef_cm256_encoder_params params,
				bef_cm256_block *blocks)
{
	int ret;
	CM256::cm256_encoder_params p = {params.OriginalCount,
					 params.RecoveryCount,
					 params.BlockBytes};
	CM256::cm256_block *b = reinterpret_cast<CM256::cm256_block *>(bef_malloc(params.OriginalCount * sizeof(CM256::cm256_block)));

	for(int i = 0; i < params.OriginalCount; i++) {
		b[i].Block = blocks[i].Block;
		b[i].Index = blocks[i].Index;
	}

	if(! cm256.isInitialized()) {
		free(b);
		return -BEF_ERR_CM256;
	}

	ret = cm256.cm256_decode(p, b);
	free(b);
	return ret;
}


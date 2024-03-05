/* SPDX-License-Identifier: GPL-3.0-or-later */
/* code file for bef command line utility
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

#include <stdio.h>
#include "bef.h"
#include <unistd.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <fcntl.h>
#include <string.h>

/* Flags as of now are -c and -d and -b and -k and -m and -n
 * Very simple experimental cmdline tool to more easily test stuff
 * will later expand to full scale command line application
 */
int main(int argc, char **argv) {
	int opt;
	int cflag = 0;
	int dflag = 0;
	uint16_t k = 0;
	uint16_t m = 0;
	uint64_t bsize = 0;
	uint32_t nblock = 0;
	bef_par_t par_t = 0;
	bef_hash_t hash_t = 0;
	int ret;
	int fd;

	while ((opt = getopt(argc, argv, "cdk:m:b:n:p:h:")) != -1) {
		switch(opt) {
		case 'c':
			cflag = 1;
			break;
		case 'd':
			dflag = 1;
			break;
		case 'k':
			k = (uint16_t) strtol(optarg, NULL, 10);
			break;
		case 'm':
			m = (uint16_t) strtol(optarg, NULL, 10);
			break;
		case 'b':
			bsize = (uint64_t) strtoll(optarg, NULL, 10);
			break;
		case 'n':
			nblock = (uint32_t) strtol(optarg, NULL, 10);
			break;
		case 'p':
			if(strcmp(optarg, "jerasure-vand") == 0)
				par_t = BEF_PAR_J_V_RS;
			else if(strcmp(optarg, "jerasure-cauchy") == 0)
				par_t = BEF_PAR_J_C_RS;
			else if(strcmp(optarg, "liberasurecode-vand") == 0)
				par_t = BEF_PAR_LE_V_RS;
			else if(strcmp(optarg, "intel-vand") == 0)
				par_t = BEF_PAR_I_V_RS;
			else if(strcmp(optarg, "intel-cauchy") == 0)
				par_t = BEF_PAR_I_C_RS;
			break;
		case 'h':
			if(strcmp(optarg, "none") == 0)
				hash_t = BEF_HASH_NONE;
			else if(strcmp(optarg, "sha1") == 0)
				hash_t = BEF_HASH_SHA1;
			else if(strcmp(optarg, "sha256") == 0)
				hash_t = BEF_HASH_SHA256;
			else if(strcmp(optarg, "sha3") == 0)
				hash_t = BEF_HASH_SHA3;
			else if(strcmp(optarg, "blake2s") == 0)
				hash_t = BEF_HASH_BLAKE2S;
			else if(strcmp(optarg, "blake3") == 0)
				hash_t = BEF_HASH_BLAKE3;
			else if(strcmp(optarg, "md5") == 0)
				hash_t = BEF_HASH_MD5;
			else if(strcmp(optarg, "crc32") == 0)
				hash_t = BEF_HASH_CRC32;
			else if(strcmp(optarg, "xxhash") == 0)
				hash_t = BEF_HASH_XXHASH;
			break;
		default:
			perror("Unknown option\n");
			break;
		}
	}

	if(cflag && dflag)
		perror("Can't construct and deconstruct at the same time\n");

	if(cflag) {
		fd = open(argv[optind], O_RDWR | O_CREAT | O_TRUNC, 0644);
		ret = bef_construct(STDIN_FILENO, fd, par_t, k, m, hash_t,
				    nblock, bsize);
		return ret;
	} else if(dflag) {
		fd = open(argv[optind], O_RDONLY);
		ret = bef_deconstruct(fd, STDOUT_FILENO);
		return ret;
	}
}


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
#include <strings.h>
#include <getopt.h>
#include <errno.h>


#define BEF_KIB	(1024)
#define BEF_KB	(1000)
#define BEF_MIB	(1024 * 1024)
#define BEF_MB	(1000 * 1000)
#define BEF_GIB	(1024 * 1024 * 1024)
#define BEF_GB	(1000 * 1000 * 1000)

void bef_help() {
	printf("bef is a command line utility that encodes and decodes\n");
	printf("erasure coded streams. More information can be found in\n");
	printf("the manpage\n\n");
	printf("-h|--help			Print this help message\n");
	printf("-v|--version			Print version of bef\n");
	printf("-c|--construct|--encode		Constructs a new BEF file\n");
	printf("-d|--deconstruct|--decode	Deconstructs an existing\n");
	printf("				BEF file\n");
	printf("-p|--preset			Set the arguments to a\n");
	printf("				given preset\n");
	printf("-r|--raw			Flag to disable reading\n");
	printf("				and/or writing the header,\n");
	printf("				You must provide the\n");
	printf("				fragment size to this\n");
	printf("				argument as well\n");
	printf("-b|--bsize			Block size for the BEF file\n");
	printf("-k|--data			Number of data fragments\n");
	printf("				per block\n");
	printf("-m|--parity			Number of parity fragments\n");
	printf("				per block\n");
	printf("-l|--interleave			Number of blocks to\n");
	printf("				to interleave\n");
	printf("-P|--parity-type		Parity type for BEF file\n");
	printf("-H|--hash-type			Hash type for BEF file\n");
	printf("-i|--input			Input file\n");
	printf("-o|--output			Output file\n\n");
}

/* More info for each in the man page */
int bef_set_preset(struct bef_real_header *header, uint64_t *bsize,
		   int preset)
{
	int ret = 0;

	/* For all of them, block size will be made such as to be equivalent to
	 * 4KiB per fragment.
	 */
	switch(preset) {
	/* "standard" preset, at the (28,24) reed solomon code used in CDs
	 * interleaved twice. Not exactly the same as CDs, as our format isn't
	 * capable of fully mimicing it, but it's close enough.
	 */
	case 0:
		*header->k = 24;
		*header->m = 4;
		*header->il_n = 2;
		*bsize = 4 * 32 * 1024;
		break;
	/* share preset, very low redundancy at around 1% (it's going over the
	 * internet with all those error corrections and likely HMACs ensuring
	 * good data traversal with SSL, so it's unlikely something'll go wrong
	 */
	case 1: //share preset, very low redundancy at around 1%
		*header->k = 100;
		*header->m = 1;
		*bsize = 4 * 101 * 1024;
		break;
	/* archive preset, high redundancy at 50% and 10 blocks interleaved so
	 * that worst case burst is ~90% of total parity.
	 */
	case 2:
		*header->k = 16;
		*header->m = 8;
		*header->il_n = 10;
		*bsize = 4 * 24 * 1024;
		break;
	/* paranoid preset, for those who are afraid that the sky'll fall down.
	 * Very high redundancy at 100% and 20 blocks interleaved so that worst
	 * case burst is ~95% of total parity.
	 */
	case 3:
		*header->k = 16;
		*header->m = 16;
		*header->il_n = 20;
		*bsize = 4 * 32 * 1024;
		break;
	default:
		ret = -BEF_ERR_INVALINPUT;
		break;
	}

	return ret;
}

uint64_t bef_convert_suffix(char *suffix)
{
	uint64_t ret = 1;

	if(strcasecmp(suffix, "K") == 0 || strcasecmp(suffix, "KIB") == 0)
		ret = BEF_KIB;
	else if(strcasecmp(suffix, "M") == 0 || strcasecmp(suffix, "MIB") == 0)
		ret = BEF_MIB;
	else if(strcasecmp(suffix, "G") == 0 || strcasecmp(suffix, "GIB") == 0)
		ret = BEF_GIB;
	else if(strcasecmp(suffix, "KB") == 0)
		ret = BEF_KB;
	else if(strcasecmp(suffix, "MB") == 0)
		ret = BEF_MB;
	else if(strcasecmp(suffix, "GB") == 0)
		ret = BEF_GB;

	return ret;
}

/* Simple command line utility that offers use of the bef file format */
int main(int argc, char **argv) {
	int opt;
	int cflag = 0;
	int dflag = 0;
	int rflag = 0;
	struct bef_real_header header = {0};
	uint64_t bsize = 0;
	int ret;
	int input = STDIN_FILENO;
	int output = STDOUT_FILENO;
	int opt_index;
	uint64_t tmp;
	char *suffix;
	int preset;
	struct option long_options[] =
			{
				{"help", no_argument, 0, 'h'},
				{"version", no_argument, 0, 'V'},
				{"construct", no_argument, 0, 'c'},
				{"encode", no_argument, 0, 'c'},
				{"deconstruct", no_argument, 0, 'd'},
				{"decode", no_argument, 0, 'd'},
				{"preset", required_argument, 0, 'p'},
				{"raw", required_argument, 0, 'r'},
				{"bsize", required_argument, 0, 'b'},
				{"data", required_argument, 0, 'k'},
				{"parity", required_argument, 0, 'm'},
				{"interleave", required_argument, 0, 'l'},
				{"parity-type", required_argument, 0, 'P'},
				{"hash-type", required_argument, 0, 'H'},
				{"input", required_argument, 0, 'i'},
				{"output", required_argument, 0, 'o'},
				{0, 0, 0, 0}
			};

	while ((opt = getopt_long(argc, argv, "hVcdp:r:k:m:b:l:P:H:i:o:",
				  long_options, &opt_index)) != -1) {
		switch(opt) {
		case 'h':
			bef_help();
			exit(EXIT_SUCCESS);
			break;
		case 'V':
			printf("bef version v0.2");
			exit(EXIT_SUCCESS);
			break;
		case 'c':
			cflag = 1;
			break;
		case 'd':
			dflag = 1;
			break;
		case 'p':
			if(strcmp(optarg, "standard") == 0)
				preset = 0;
			else if(strcmp(optarg, "share") == 0)
				preset = 1;
			else if(strcmp(optarg, "archive") == 0)
				preset = 2;
			else if(strcmp(optarg, "paranoid") == 0)
				preset = 3;

			if(bef_set_preset(&header, &bsize, preset) != 0) {
				fprintf(stderr,
					"Input a proper value for -p!\n");
				exit(-BEF_ERR_INVALINPUT);
			}
			break;
		case 'r':
			rflag = 1;
			header.nbyte = (uint64_t) strtoll(optarg, &suffix, 10);
			if((header.nbyte == UINT64_MAX || header.nbyte == 0) &&
			   errno == ERANGE) {
				fprintf(stderr,
					"Input a proper value for -B!\n");
				exit(-BEF_ERR_INVALINPUT);
			}
			header.nbyte *= bef_convert_suffix(suffix);
			break;
		case 'k':
			tmp = (uint64_t) strtol(optarg, NULL, 10);
			if(tmp > UINT16_MAX) {
				fprintf(stderr,
					"Input a proper value for -k!\n");
				exit(-BEF_ERR_INVALINPUT);
			}
			header.k = (uint16_t) tmp;
			break;
		case 'm':
			tmp = (uint64_t) strtol(optarg, NULL, 10);
			if(tmp > UINT16_MAX) {
				fprintf(stderr,
					"Input a proper value for -m!\n");
				exit(-BEF_ERR_INVALINPUT);
			}
			header.m = (uint16_t) tmp;
			break;
		case 'b':
			bsize = (uint64_t) strtoll(optarg, &suffix, 10);
			if((bsize == UINT64_MAX || bsize == 0) &&
			   errno == ERANGE) {
				fprintf(stderr,
					"Input a proper value for -b!\n");
				exit(-BEF_ERR_INVALINPUT);
			}
			bsize *= bef_convert_suffix(suffix);
			break;
		case 'l':
			tmp = (uint64_t) strtol(optarg, NULL, 10);
			if(tmp > UINT16_MAX) {
				fprintf(stderr,
					"Input a proper value for -l!\n");
				exit(-BEF_ERR_INVALINPUT);
			}
			header.il_n = (uint16_t) tmp;
			break;
		case 'P':
			if(strcmp(optarg, "jerasure-vand") == 0) {
				header.par_t = BEF_PAR_J_V_RS;
			} else if(strcmp(optarg, "jerasure-cauchy") == 0) {
				header.par_t = BEF_PAR_J_C_RS;
			} else if(strcmp(optarg, "liberasurecode-vand") == 0) {
				header.par_t = BEF_PAR_LE_V_RS;
			} else if(strcmp(optarg, "intel-vand") == 0) {
				header.par_t = BEF_PAR_I_V_RS;
			} else if(strcmp(optarg, "intel-cauchy") == 0) {
				header.par_t = BEF_PAR_I_C_RS;
			} else if(strcmp(optarg, "fec-vand") == 0) {
				header.par_t = BEF_PAR_F_V_RS;
			} else {
				fprintf(stderr,
					"Input a proper value for -P!\n");
				exit(-BEF_ERR_INVALINPUT);
			}
			break;
		case 'H':
			if(strcmp(optarg, "none") == 0) {
				header.hash_t = BEF_HASH_NONE;
			} else if(strcmp(optarg, "sha1") == 0) {
				header.hash_t = BEF_HASH_SHA1;
			} else if(strcmp(optarg, "sha256") == 0) {
				header.hash_t = BEF_HASH_SHA256;
			} else if(strcmp(optarg, "sha3") == 0) {
				header.hash_t = BEF_HASH_SHA3;
			} else if(strcmp(optarg, "blake2s") == 0) {
				header.hash_t = BEF_HASH_BLAKE2S;
			} else if(strcmp(optarg, "blake3") == 0) {
				header.hash_t = BEF_HASH_BLAKE3;
			} else if(strcmp(optarg, "md5") == 0) {
				header.hash_t = BEF_HASH_MD5;
			} else if(strcmp(optarg, "crc32") == 0) {
				header.hash_t = BEF_HASH_CRC32;
			} else if(strcmp(optarg, "xxhash") == 0) {
				header.hash_t = BEF_HASH_XXHASH;
			} else {
				fprintf(stderr,
					"Input a proper value for -H!\n");
				exit(-BEF_ERR_INVALINPUT);
			}
			break;
		case 'i':
			input = open(optarg, O_RDONLY);
			break;
		case 'o':
			output = open(optarg, O_RDWR | O_CREAT | O_TRUNC, 0644);
			break;
		default:
			break;
		}
	}

	if(cflag && dflag) {
		fprintf(stderr,
			"Can't construct and deconstruct at the same time\n");
		exit(-BEF_ERR_INVALINPUT);
	}

	if(cflag) {
		ret = bef_construct(input, output, bsize, header, rflag);
		return ret;
	} else if(dflag) {
		ret = bef_deconstruct(input, output, header, rflag);
		return ret;
	}
}


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

#include "bef.h"
#include <stdio.h>
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

/* Our verbosity flag */
uint8_t bef_vflag = 0;

/* Our raw flag */
uint8_t bef_rflag = 0;

/* Our padding flag */
uint8_t bef_mflag = 0;

/* Our number of threads */
uint16_t bef_numT = 0;

void bef_help(void) {
printf("bef is a command line utility that encodes and decodes erasure coded streams.\n");
printf("More information can be found in the manpage\n\n");
printf("-h|--help			Print this help message\n");
printf("-V|--version			Print version of bef\n");
printf("-v|--verbose			Print verbose output to stderr\n");
printf("-c|--construct|--encode		Constructs a new BEF file\n");
printf("-d|--deconstruct|--decode	Deconstructs an existing BEF file\n");
printf("-M|--minimize			Minimize the given block size if the incoming\n");
printf("				stream is small\n");
printf("-p|--preset			Set the arguments to a given preset\n");
printf("-r|--raw			Flag to disable reading and/or writing the\n");
printf("				header, You must provide the fragment size to\n");
printf("				argument as well\n");
printf("-b|--bsize			Block size for the BEF file\n");
printf("-k|--data			Number of data fragments per block\n");
printf("-m|--parity			Number of parity fragments per block\n");
printf("-l|--interleave			Number of blocks to interleave\n");
printf("-P|--parity-type		Parity type for BEF file\n");
printf("-H|--hash-type			Hash type for BEF file\n");
printf("-s|--scan			Number of bytes to scan for misplaced fragments\n");
printf("-T|--threads			Number of threads to use concurrently\n");
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
		header->k = 24;
		header->m = 8;
		header->il_n = 2;
		*bsize = 4 * 24 * 1024;
		break;
	/* share preset, very low redundancy at around 1% (it's going over the
	 * internet with all those error corrections and likely HMACs ensuring
	 * good data traversal with SSL, so it's unlikely something'll go wrong
	 */
	case 1: //share preset, very low redundancy at around 1%
		header->k = 100;
		header->m = 1;
		*bsize = 4 * 100 * 1024;
		break;
	/* archive preset, high redundancy at 50% and 10 blocks interleaved so
	 * that worst case burst is ~90% of total parity.
	 */
	case 2:
		header->k = 16;
		header->m = 8;
		header->il_n = 10;
		*bsize = 4 * 16 * 1024;
		break;
	/* paranoid preset, for those who are afraid that the sky'll fall down.
	 * Very high redundancy at 100% and 20 blocks interleaved so that worst
	 * case burst is ~95% of total parity.
	 */
	case 3:
		header->k = 16;
		header->m = 16;
		header->il_n = 20;
		*bsize = 4 * 16 * 1024;
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
	struct bef_real_header header = {0};
	uint64_t bsize = 0;
	uint64_t sbyte = 0;
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
				{"verbose", no_argument, 0, 'v'},
				{"construct", no_argument, 0, 'c'},
				{"encode", no_argument, 0, 'c'},
				{"deconstruct", no_argument, 0, 'd'},
				{"decode", no_argument, 0, 'd'},
				{"minimize", no_argument, 0, 'M'},
				{"preset", required_argument, 0, 'p'},
				{"raw", required_argument, 0, 'r'},
				{"bsize", required_argument, 0, 'b'},
				{"data", required_argument, 0, 'k'},
				{"parity", required_argument, 0, 'm'},
				{"interleave", required_argument, 0, 'l'},
				{"parity-type", required_argument, 0, 'P'},
				{"hash-type", required_argument, 0, 'H'},
				{"scan", required_argument, 0, 's'},
				{"threads", required_argument, 0, 'T'},
				{"input", required_argument, 0, 'i'},
				{"output", required_argument, 0, 'o'},
				{0, 0, 0, 0}
			};

	while ((opt = getopt_long(argc, argv, "hVvcdMp:r:k:m:b:l:P:H:s:T:i:o:",
				  long_options, &opt_index)) != -1) {
		switch(opt) {
		case 'h':
			bef_help();
			exit(EXIT_SUCCESS);
			break;
		case 'V':
			printf("bef version v0.2.2\n");
			exit(EXIT_SUCCESS);
			break;
		case 'v':
			bef_vflag++;
			break;
		case 'c':
			cflag = 1;
			break;
		case 'd':
			dflag = 1;
			break;
		case 'M':
			bef_mflag = 1;
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
			else
				preset = -1;

			if(bef_set_preset(&header, &bsize, preset) != 0) {
				fprintf(stderr,
					"Input a proper value for -p!\n");
				exit(-BEF_ERR_INVALINPUT);
			}
			break;
		case 'r':
			bef_rflag = 1;
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
			} else if(strcmp(optarg, "cm256-cauchy") == 0) {
				header.par_t = BEF_PAR_CM_C_RS;
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
		case 's':
			sbyte = (uint64_t) strtoll(optarg, &suffix, 10);
			if((sbyte == UINT64_MAX || sbyte == 0) &&
			   errno == ERANGE) {
				fprintf(stderr,
					"Input a proper value for -b!\n");
				exit(-BEF_ERR_INVALINPUT);
			}
			sbyte *= bef_convert_suffix(suffix);
			break;
		case 'T':
			tmp = (uint64_t) strtol(optarg, NULL, 10);
			if(tmp > UINT16_MAX) {
				fprintf(stderr,
					"Input a proper value for -k!\n");
				exit(-BEF_ERR_INVALINPUT);
			}
			bef_numT = (uint16_t) tmp;
			break;
		case 'i':
			input = open(optarg, O_RDONLY);
			if(input == -1) {
				perror("Error opening input file");
				exit(-BEF_ERR_INVALINPUT);
			}
			break;
		case 'o':
			output = open(optarg, O_RDWR | O_CREAT | O_TRUNC, 0644);
			if(output == -1) {
				perror("Error creating output file");
				exit(-BEF_ERR_INVALINPUT);
			}
			break;
		default:
			break;
		}
	}

	if(header.k + header.m > bef_max_frag(header.par_t)) {
		fprintf(stderr,
			"ERROR: number of fragments (%u) is greater than the maximum number for this parity type (%u)\n",
			header.k + header.m, bef_max_frag(header.par_t));
		exit(-BEF_ERR_INVALINPUT);
	}

	if(cflag && dflag) {
		fprintf(stderr,
			"ERROR: Can't construct and deconstruct at the same time\n");
		exit(-BEF_ERR_INVALINPUT);
	}

	if(cflag) {
		ret = bef_construct(input, output, bsize, header);
		return ret;
	} else if(dflag) {
		ret = bef_deconstruct(input, output, header, sbyte);
		return ret;
	}
}


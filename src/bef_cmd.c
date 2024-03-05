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
	int ret;
	int fd;

	while ((opt = getopt(argc, argv, "cdk:m:b:n:")) != -1) {
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
		default:
			perror("Unknown option\n");
			break;
		}
	}

	if(cflag && dflag)
		perror("Can't construct and deconstruct at the same time\n");

	if(cflag) {
		fd = open(argv[optind], O_RDWR | O_CREAT | O_TRUNC, 0644);
		ret = bef_construct(STDIN_FILENO, fd, 0, k, m, 0, 0, bsize);
		return ret;
	} else if(dflag) {
		fd = open(argv[optind], O_RDONLY);
		ret = bef_deconstruct(fd, STDOUT_FILENO);
		return ret;
	}
}


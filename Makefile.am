## SPDX-License-Identifier: GPL-3.0-or-later
## Makefile.am for bef project
## Copyright (C) 2024 gbletr42
##
## This program is free software: you can redistribute it and/or modify it
## under the terms of the GNU General Public License as published by the Free
## Software Foundation, either version 3 of the License, or (at your option)
## any later version.
##
## This program is distributed in the hope that it will be useful, but WITHOUT
## ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
## FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
## more details.
##
## You should have received a copy of the GNU General Public License along with
## this program. If not, see <https://www.gnu.org/licenses/>.

AUTOMAKE_OPTIONS = subdir-objects

CFLAGS += -Wall -Wextra -Wno-sign-compare $(OPENMP_CFLAGS)

bin_PROGRAMS = bef
bef_SOURCES = src/bef.c src/bef_cmd.c src/zfec.c
bef_LDADD = -lxxhash
if BLAKE3
bef_LDADD += -lblake3
endif
if ZLIB
bef_LDADD += -lz
endif
if OPENSSL
bef_LDADD += -lcrypto
endif
if LIBERASURECODE
bef_LDADD += -lerasurecode
endif

man_MANS = doc/bef.1

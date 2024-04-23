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

CFLAGS += -Wall -Wextra -Wpedantic -Wno-sign-compare -Wpadded -Wcast-align -Wstrict-aliasing -Wpointer-arith -Winit-self -Wshadow -Wswitch-enum -Wstrict-prototypes -Wmissing-prototypes -Wredundant-decls -Wfloat-equal -Wundef -Wdeclaration-after-statement -Wvla $(OPENMP_CFLAGS)
CXXFLAGS += $(CFLAGS)

bin_PROGRAMS = bef
bef_SOURCES = src/bef.c src/bef_cmd.c src/zfec.c
bef_LDADD = -lxxhash

if BLAKE3
bef_LDADD += -lblake3
endif

if ZLIBNG
bef_LDADD += -lz-ng
else
if ZLIB
bef_LDADD += -lz
endif
endif

if OPENSSL
bef_LDADD += -lcrypto
endif

if LIBERASURECODE
bef_LDADD += -lerasurecode
endif

if CM256CC
bef_CXXFLAGS = $(CXXFLAGS) -DUSE_SSSE3 #won't build on Arch otherwise...
bef_SOURCES += src/cm256.cc
bef_LDADD += -lcm256cc -lstdc++
endif

if OPENFEC
bef_LDADD += -lopenfec
endif

if LEOPARD
bef_LDADD += -lleopard
endif

if WIREHAIR
bef_LDADD += -lwirehair
endif

man_MANS = doc/bef.1

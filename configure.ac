dnl SPDX-License-Identifier: GPL-3.0-or-later
dnl configure.ac for bef project
dnl Copyright (C) 2024 gbletr42
dnl
dnl This program is free software: you can redistribute it and/or modify it
dnl under the terms of the GNU General Public License as published by the Free
dnl Software Foundation, either version 3 of the License, or (at your option)
dnl any later version.
dnl
dnl This program is distributed in the hope that it will be useful, but WITHOUT
dnl ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
dnl FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
dnl more details.
dnl
dnl You should have received a copy of the GNU General Public License along with
dnl this program. If not, see <https://www.gnu.org/licenses/>.

AC_PREREQ(2.62)
AC_INIT([bef], [0.2.2], [gbletr42@gmail.com])
AC_CONFIG_SRCDIR([src/bef.c])

AC_CONFIG_HEADERS([config.h])
AM_INIT_AUTOMAKE([foreign])

AC_PROG_CC
AC_PROG_INSTALL

AC_LANG(C)

dnl Due to it being default, I'll make XXHASH mandatory
AC_CHECK_HEADER([xxhash.h], [], [AC_MSG_ERROR(xxHash is a required dependency of this software package)])

dnl Enable Third Party packages
AC_ARG_WITH([blake3], [AS_HELP_STRING([--with-blake3], [enable BLAKE3 support])], [AC_DEFINE([BEF_BLAKE3], 1, [enables BLAKE3 support]) AC_CHECK_HEADERS([blake3.h]) blake3=yes], [])
AC_ARG_WITH([zlib], [AS_HELP_STRING([--with-zlib], [enable zlib support])], [AC_DEFINE([BEF_ZLIB], 1, [enables zlib support]) AC_CHECK_HEADERS([zlib.h]) zlib=yes], [])
AC_ARG_WITH([openssl], [AS_HELP_STRING([--with-openssl], [enable OpenSSL support])], [AC_DEFINE([BEF_OPENSSL], 1, [enables OpenSSL support]) AC_CHECK_HEADERS([openssl/evp.h]) openssl=yes], [])
AC_ARG_WITH([liberasurecode], [AS_HELP_STRING([--with-liberasurecode], [enable liberasurecode support])], [AC_DEFINE([BEF_LIBERASURECODE], 1, [enables liberasurecode support]) AC_CHECK_HEADERS([erasurecode.h]) erasurecode=yes], [])
AC_CHECK_HEADERS([jerasure.h] [isa-l.h])

dnl Check some specific structs and such
AC_TYPE_SIZE_T
AC_SYS_LARGEFILE

dnl Conditionals for options
AM_CONDITIONAL([BLAKE3], [test "$blake3" == "yes"])
AM_CONDITIONAL([ZLIB], [test "$zlib" == "yes"])
AM_CONDITIONAL([OPENSSL], [test "$openssl" == "yes"])
AM_CONDITIONAL([LIBERASURECODE], [test "$erasurecode" == "yes"])

AC_CONFIG_FILES([Makefile])
AC_OUTPUT

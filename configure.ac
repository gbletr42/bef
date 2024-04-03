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
AC_PROG_CXX
AC_PROG_INSTALL
AC_PROG_RANLIB

AC_LANG(C)
AC_OPENMP

dnl Due to it being default, I'll make XXHASH mandatory
AC_CHECK_HEADER([xxhash.h], [], [AC_MSG_ERROR(xxHash is a required dependency of this software package)])

dnl Enable Third Party packages
AC_ARG_WITH([blake3], [AS_HELP_STRING([--with-blake3], [enable BLAKE3 support])], [AC_DEFINE([BEF_BLAKE3], 1, [enables BLAKE3 support]) AC_CHECK_HEADERS([blake3.h]) blake3=yes], [])
AC_ARG_WITH([zlib], [AS_HELP_STRING([--with-zlib], [enable zlib support])], [AC_DEFINE([BEF_ZLIB], 1, [enables zlib support]) AC_CHECK_HEADERS([zlib.h]) zlib=yes], [])
if test "$zlib" == "yes"
then
	AC_CHECK_HEADERS([zlib-ng.h], [AC_DEFINE([BEF_ZLIB_NG], 1, [enables zlib-ng support]) zlibng=yes])
fi
AC_ARG_WITH([openssl], [AS_HELP_STRING([--with-openssl], [enable OpenSSL support])], [AC_DEFINE([BEF_OPENSSL], 1, [enables OpenSSL support]) AC_CHECK_HEADERS([openssl/evp.h]) openssl=yes], [])
AC_ARG_WITH([liberasurecode], [AS_HELP_STRING([--with-liberasurecode], [enable liberasurecode support])], [AC_DEFINE([BEF_LIBERASURECODE], 1, [enables liberasurecode support]) AC_CHECK_HEADERS([erasurecode.h]) erasurecode=yes], [])
AC_ARG_WITH([cm256cc], [AS_HELP_STRING([--with-cm256cc], [enable cm256cc support])], [AC_DEFINE([BEF_CM256CC], 1, [enables cm256cc support]) cm256cc=yes], [])
AC_ARG_WITH([openfec], [AS_HELP_STRING([--with-openfec], [enable openfec support])], [AC_DEFINE([BEF_OPENFEC], 1, [enables openfec support]) openfec=yes], [])
AC_ARG_WITH([leopard], [AS_HELP_STRING([--with-leopard], [enable leopard support])], [AC_DEFINE([BEF_LEOPARD], 1, [enables leopard support]) leopard=yes], [])
AC_ARG_WITH([wirehair], [AS_HELP_STRING([--with-wirehair], [enable wirehair support])], [AC_DEFINE([BEF_WIREHAIR], 1, [enables wirehair support]) wirehair=yes], [])
AC_CHECK_HEADERS([jerasure.h] [isa-l.h])

dnl Check some specific structs and such
AC_TYPE_SIZE_T
AC_SYS_LARGEFILE

dnl Conditionals for options
AM_CONDITIONAL([BLAKE3], [test "$blake3" == "yes"])
AM_CONDITIONAL([ZLIB], [test "$zlib" == "yes"])
AM_CONDITIONAL([ZLIBNG], [test "$zlibng" == "yes"])
AM_CONDITIONAL([OPENSSL], [test "$openssl" == "yes"])
AM_CONDITIONAL([LIBERASURECODE], [test "$erasurecode" == "yes"])
AM_CONDITIONAL([CM256CC], [test "$cm256cc" == "yes"])
AM_CONDITIONAL([OPENFEC], [test "$openfec" == "yes"])
AM_CONDITIONAL([LEOPARD], [test "$leopard" == "yes"])
AM_CONDITIONAL([WIREHAIR], [test "$wirehair" == "yes"])

AC_CONFIG_FILES([Makefile])
AC_OUTPUT

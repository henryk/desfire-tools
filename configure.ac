dnl Process this file with autoconf to produce a configure script.

AC_PREREQ(2.59)
AC_INIT(desfire-tools, 1.0)


AC_CANONICAL_SYSTEM
AM_INIT_AUTOMAKE()

AC_PROG_CC

AM_PROG_CC_C_O 
AC_PROG_CC_C99

PKG_CHECK_MODULES([DEPS], [libnfc >= 1.7.0 libfreefare >= 0.3.5])

AC_CONFIG_FILES(Makefile src/Makefile)
AC_OUTPUT


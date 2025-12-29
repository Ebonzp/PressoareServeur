#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT(pressoare-b2b-server, 1.2, bug@pressoare.com)
AM_INIT_AUTOMAKE

AC_MSG_CHECKING([whether configure should try to set CFLAGS])
AS_IF([test "x${CFLAGS+set}" = xset], [enable_cflags_setting=no], [enable_cflags_setting=yes])
AC_MSG_RESULT($enable_cflags_setting)

# Checks for programs.
AC_PROG_CC

# Checks for libraries.
AC_CHECK_LIB([crypto], [SHA1], [], [AC_MSG_FAILURE([could not find libcrypto (of OpenSSL)])])

# Checks for header files.
AC_CHECK_HEADERS([ctype.h errno.h fnctl.h getopt.h netdb.h openssl/sha.h semaphore.h signal.h stdarg.h stdio.h stdlib.h string.h syslog.h sys/mman.h sys/personality.h sys/socket.h sys/stat.h sys/types.h sys/wait.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.

# Checks for library functions.
AC_FUNC_FORK
AC_FUNC_MALLOC
AC_FUNC_REALLOC
AC_CHECK_FUNCS([memset socket strerror])

ACX_PTHREAD


AC_ARG_ENABLE([ssp], AS_HELP_STRING([--enable-ssp], [Enable stack protection for better security]))
AC_ARG_ENABLE([pie], AS_HELP_STRING([--enable-pie], [Enable PIE compilation for better security]))
AC_ARG_ENABLE([sepcode], AS_HELP_STRING([--enable-sepcode], [Enable separate-code linker option for better security]))

AS_IF([test "x$enable_ssp" = "xyes"], [ ssp="-fstack-protector -DSSP" ], [ssp="-fno-stack-protector"])
AS_IF([test "x$enable_pie" = "xyes"], [ pie="-pie" ], [pie="-no-pie"])
AS_IF([test "x$enable_sepcode" = "xyes"], [ sepcode="-Wl,-zseparate-code" ], [sepcode="-Wl,-znoseparate-code"])


test "x$enable_cflags_setting" = xyes && CFLAGS="-Wall -Wextra -O0 -m32 -g -fdebug-prefix-map=$ac_abs_confdir=. $pie $ssp $sepcode"

AC_CONFIG_FILES([
        Makefile
        src/Makefile
        ])

AC_OUTPUT

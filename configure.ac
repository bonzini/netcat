# Process this file with autoconf to produce a configure script.
AC_INIT(nc, 2.0, bonzini@gnu.org)
AC_CONFIG_AUX_DIR([config])
AC_CONFIG_SRCDIR([netcat.c])
AC_CONFIG_HEADER([config.h])
AM_INIT_AUTOMAKE

# Checks for programs.
AC_PROG_CC

# Checks for libraries.
AC_CHECK_LIB(nsl, gethostbyname)
AC_CHECK_LIB(socket, socket)

# Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS(fcntl.h sys/file.h getopt.h poll.h)

if test $ac_cv_header_poll_h = no; then
  AC_CONFIG_LINKS(poll.h:poll_.h)
  AC_LIBOBJ(poll)
fi

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_SIZE_T
AC_HEADER_TIME

# Checks for library functions.
AC_FUNC_VPRINTF
AC_TYPE_SIGNAL
AC_CHECK_FUNCS(strchr strrchr)
AC_CHECK_TYPE(sigjmp_buf,
  [AC_DEFINE(HAVE_SIGSETJMP, 1, [Define to 1 if you have sigsetjmp & friends])],
  [],
  [#include <signal.h>
  #include <setjmp.h>])

AC_REPLACE_FUNCS(dup2 strtoul)

# TODO:
# also check for arpa/inet.h netdb.h netinet/in.h poll.h
# also check for alarm getaddrinfo random poll socket

AC_CONFIG_FILES([Makefile])
AC_OUTPUT

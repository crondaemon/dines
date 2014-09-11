AC_INIT([Dines], [0.5.3], [lomato@gmail.com], [dines], [http://github.com/crondaemon/dines])
AC_PREREQ([2.59])
AM_INIT_AUTOMAKE([1.10 no-define foreign])
AC_CONFIG_HEADERS([config.h])
AC_PROG_CXX
AC_CONFIG_FILES([Makefile])
AC_ARG_ENABLE(gcov,
    AC_HELP_STRING([--enable-gcov],[Enable gcov code coverage (requires GCC)]), [CXXFLAGS="-g -ftest-coverage -fprofile-arcs"])
AC_OUTPUT

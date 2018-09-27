# -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

# This file is part of PulseAudio.
#
# Copyright 2004-2008 Lennart Poettering
# Copyright 2006-2007 Pierre Ossman <ossman@cendio.se> for Cendio AB
#
# PulseAudio is free software; you can redistribute it and/or modify it
# under the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# PulseAudio is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with PulseAudio; if not, see <http://www.gnu.org/licenses/>.

AC_PREREQ(2.63)

AC_INIT([pulseaudio],[m4_esyscmd(./git-version-gen .tarball-version)],[pulseaudio-discuss (at) lists (dot) freedesktop (dot) org],[pulseaudio],[http://pulseaudio.org/])
AC_CONFIG_SRCDIR([src/daemon/main.c])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_AUX_DIR([build-aux])
AM_INIT_AUTOMAKE([foreign 1.11 -Wall -Wno-portability subdir-objects silent-rules color-tests dist-xz tar-ustar])

AS_IF([! test -n "$VERSION"], [
   AC_MSG_ERROR([git-version-gen failed])
])

m4_define(pa_major, `echo $VERSION | cut -d. -f1 | cut -d- -f1`)
m4_define(pa_minor, `echo $VERSION | cut -d. -f2 | cut -d- -f1`)

AC_SUBST(PA_MAJOR, pa_major)
AC_SUBST(PA_MINOR, pa_minor)
AC_SUBST(PA_MAJORMINOR, pa_major.pa_minor)

AC_SUBST(PA_API_VERSION, 12)
AC_SUBST(PA_PROTOCOL_VERSION, 32)

# The stable ABI for client applications, for the version info x:y:z
# always will hold y=z
AC_SUBST(LIBPULSE_VERSION_INFO, [20:3:20])

# A simplified, synchronous, ABI-stable interface for client
# applications, for the version info x:y:z always will hold y=z
AC_SUBST(LIBPULSE_SIMPLE_VERSION_INFO, [1:1:1])

# The ABI-stable GLib adapter for client applications, for the version
# info x:y:z always will hold y=z
AC_SUBST(LIBPULSE_MAINLOOP_GLIB_VERSION_INFO, [0:5:0])

AC_CANONICAL_HOST
AC_DEFINE_UNQUOTED([CANONICAL_HOST], "$host", [Canonical host string.])

AC_CHECK_PROG([STOW], [stow], [yes], [no])

AS_IF([test "x$STOW" = "xyes" && test -d /usr/local/stow], [
    AC_MSG_NOTICE([*** Found /usr/local/stow: default install prefix set to /usr/local/stow/${PACKAGE_NAME}-${PACKAGE_VERSION} ***])
    ac_default_prefix="/usr/local/stow/${PACKAGE_NAME}-${PACKAGE_VERSION}"
])

AM_SILENT_RULES([yes])


#### Checks for programs. ####

# mkdir -p

AC_PROG_MKDIR_P

# ln -s

AC_PROG_LN_S

# CC

AC_PROG_CC
AM_PROG_CC_C_O
# Only required if you want the WebRTC canceller -- no runtime dep on
# libstdc++ otherwise
AC_PROG_CXX
AC_PROG_GCC_TRADITIONAL
AC_USE_SYSTEM_EXTENSIONS
AX_CXX_COMPILE_STDCXX_11([ext],[optional])

# M4

AC_CHECK_PROGS([M4], gm4 m4, no)
AS_IF([test "x$M4" = "xno"], AC_MSG_ERROR([m4 missing]))

# pkg-config

PKG_PROG_PKG_CONFIG

# gettext

AM_GNU_GETTEXT_VERSION([0.19.8])
AM_GNU_GETTEXT([external])

GETTEXT_PACKAGE=pulseaudio
AC_SUBST([GETTEXT_PACKAGE])
AC_DEFINE_UNQUOTED([GETTEXT_PACKAGE],["$GETTEXT_PACKAGE"],[Gettext package])


#### Determine host OS ####

# if the host has the possibility of sys/capability.h for dropping privileges
# used to determine if we should error out if it is not found
host_has_caps=0

os_is_linux=0
os_is_win32=0
os_is_darwin=0

AC_MSG_CHECKING([host operating system])
case "$host_os" in
    linux*)
        AC_MSG_RESULT([linux])
        host_has_caps=1
        os_is_linux=1
    ;;
    freebsd*)
        AC_MSG_RESULT([freebsd])
        host_has_caps=1
    ;;
    netbsd*)
        AC_MSG_RESULT([netbsd])
    ;;
    darwin*)
        AC_MSG_RESULT([darwin])
        os_is_darwin=1
        AC_DEFINE([OS_IS_DARWIN], 1, [Build target is Darwin.])
    ;;
    mingw*)
        AC_MSG_RESULT([win32])
        os_is_win32=1
        AC_DEFINE([OS_IS_WIN32], 1, [Build target is Windows.])
    ;;
    *)
        AC_MSG_RESULT([unknown])
    ;;
esac

AM_CONDITIONAL(OS_IS_DARWIN, test "x$os_is_darwin" = "x1")
AM_CONDITIONAL(OS_IS_WIN32, test "x$os_is_win32" = "x1")
AC_SUBST([OS_IS_WIN32], [$os_is_win32])

# Platform specific hacks
case "$host_os" in
    darwin* )
        AC_DEFINE([_DARWIN_C_SOURCE], [200112L], [Needed to get NSIG on Mac OS X])
    ;;
    mingw* )
        AC_DEFINE([WIN32_LEAN_AND_MEAN], 1, [Needed to avoid including unnecessary headers on Windows])
    ;;
    solaris* )
        AC_DEFINE(_XOPEN_SOURCE,       600, [Needed to get declarations for msg_control and msg_controllen on Solaris])
        AC_DEFINE(__EXTENSIONS__,        1, [Needed to get declarations for msg_control and msg_controllen on Solaris])
    ;;
esac


#### Compiler flags ####

AX_CHECK_COMPILE_FLAG([-std=gnu11],
   [],
   [AC_MSG_ERROR([*** Compiler does not support -std=gnu11])],
   [-pedantic -Werror])

AX_APPEND_COMPILE_FLAGS(
    [-Wall -W -Wextra -pipe -Wno-long-long -Wno-overlength-strings -Wunsafe-loop-optimizations -Wundef -Wformat=2 -Wlogical-op -Wsign-compare -Wformat-security -Wmissing-include-dirs -Wformat-nonliteral -Wold-style-definition -Wpointer-arith -Winit-self -Wdeclaration-after-statement -Wfloat-equal -Wmissing-prototypes -Wstrict-prototypes -Wredundant-decls -Wmissing-declarations -Wmissing-noreturn -Wshadow -Wendif-labels -Wcast-align -Wstrict-aliasing -Wwrite-strings -Wno-unused-parameter -ffast-math -fno-common -fdiagnostics-show-option -fdiagnostics-color=auto],
    [], [-pedantic -Werror])

AS_CASE([" $CFLAGS "], [*" -O0 "*], [], [
    # Don't append the flag if it already exists.
    # Only enable fastpath asserts when doing a debug build, e.g. from bootstrap.sh.
    AX_APPEND_FLAG([-DFASTPATH], [CPPFLAGS])

    # Cannot use AX_APPEND_FLAG here, as it assumes no space inside the added flags.
    # Cannot append flags with AX_APPEND_FLAG one by one, as this would destroy all fortifications
    # if CPPFLAGS already contain -D_FORTIFY_SOURCE=2.

    # Warnings to be aware of that appear with -D_FORTIFY_SOURCE=2 but without -U_FORTIFY_SOURCE:
    # On Fedora 20 with -O0: #warning _FORTIFY_SOURCE requires compiling with optimization (-O) [-Wcpp]
    # On Gentoo with -O2:    "_FORTIFY_SOURCE" redefined [enabled by default]
    AS_VAR_APPEND([CPPFLAGS],[" -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=2"])
])

#### Linker flags ####

# Check whether the linker supports the -version-script option.
# The Make variable $(srcdir) needs to be in the LDFLAGS in that form,
# so that it is expanded the right way in every subdir.
AX_CHECK_LINK_FLAG(["-Wl,-version-script=${srcdir}/src/map-file"],
    [VERSIONING_LDFLAGS='-Wl,-version-script=$(abs_top_srcdir)/src/map-file'])
AC_SUBST([VERSIONING_LDFLAGS])

# Use immediate (now) bindings; avoids the funky re-call in itself.
# The -z now syntax is lifted from Sun's linker and works with GNU's too, other linkers might be added later.
AX_APPEND_LINK_FLAGS([-Wl,-z,now], [IMMEDIATE_LDFLAGS])
AC_SUBST([IMMEDIATE_LDFLAGS])
AS_CASE([$IMMEDIATE_LDFLAGS],[*-z,now*],
    [AC_DEFINE([HAVE_BIND_NOW],[1],
               [Define to 1 if immediate binding is available])])

# On ELF systems we don't want the libraries to be unloaded since we don't clean them up properly,
# so we request the nodelete flag to be enabled.
# On other systems, we don't really know how to do that, but it's welcome if somebody can tell.
AX_APPEND_LINK_FLAGS([-Wl,-z,nodelete], [NODELETE_LDFLAGS], [-shared])
AC_SUBST([NODELETE_LDFLAGS])

# Check for the proper way to build libraries that have no undefined symbols
case $host in
    # FreeBSD (et al.) does not complete linking for shared objects when pthreads
    # are requested, as different implementations are present.
    *-freebsd* | *-openbsd*) ;;
    *)
        for possible_flag in "-Wl,--no-undefined" "-Wl,-z,defs"; do
            AX_CHECK_LINK_FLAG([$possible_flag], [NOUNDEFINED_LDFLAGS="$possible_flag"; break])
        done
    ;;
esac
AC_SUBST([NOUNDEFINED_LDFLAGS])


#### Atomic operations ####

# Native atomic operation support
AC_ARG_ENABLE([atomic-arm-linux-helpers],
    AS_HELP_STRING([--disable-atomic-arm-linux-helpers],[use inline asm or libatomic_ops instead]))

AC_ARG_ENABLE([atomic-arm-memory-barrier],
    AS_HELP_STRING([--enable-atomic-arm-memory-barrier],[only really needed in SMP arm systems]))

if test "x$enable_atomic_arm_memory_barrier" = "xyes"; then
    AC_DEFINE_UNQUOTED(ATOMIC_ARM_MEMORY_BARRIER_ENABLED, 1, [Enable memory barriers])
fi

# If everything else fails use libatomic_ops
need_libatomic_ops=yes

AC_CACHE_CHECK([whether $CC knows __sync_bool_compare_and_swap()],
    pulseaudio_cv_sync_bool_compare_and_swap, [
    AC_LINK_IFELSE(
        [AC_LANG_PROGRAM([], [[int a = 4; __sync_bool_compare_and_swap(&a, 4, 5);]])],
        [pulseaudio_cv_sync_bool_compare_and_swap=yes],
        [pulseaudio_cv_sync_bool_compare_and_swap=no])
    ])

if test "$pulseaudio_cv_sync_bool_compare_and_swap" = "yes" ; then
    AC_DEFINE([HAVE_ATOMIC_BUILTINS], 1, [Have __sync_bool_compare_and_swap() and friends.])
    need_libatomic_ops=no
else
    # HW specific atomic ops stuff
    AC_MSG_CHECKING([architecture for native atomic operations])
    case $host in
        *-netbsd*)
            AC_MSG_RESULT([yes])
            need_libatomic_ops=no
        ;;
        arm*)
            AC_MSG_RESULT([arm])
            AC_MSG_CHECKING([whether we can use Linux kernel helpers])
            # The Linux kernel helper functions have been there since 2.6.16. However
            # compile time checking for kernel version in cross compile environment
            # (which is usually the case for arm cpu) is tricky (or impossible).
            if test "x$os_is_linux" = "x1" && test "x$enable_atomic_arm_linux_helpers" != "xno"; then
                AC_MSG_RESULT([yes])
                AC_DEFINE_UNQUOTED(ATOMIC_ARM_LINUX_HELPERS, 1, [special arm linux implementation])
                need_libatomic_ops=no
            else
                AC_MSG_RESULT([no])
                AC_CACHE_CHECK([compiler support for arm inline asm atomic operations],
                    pulseaudio_cv_support_arm_atomic_ops, [
                    AC_COMPILE_IFELSE(
                        [AC_LANG_PROGRAM([], [[
                            volatile int a=0;
                            int o=0, n=1, r;
                            asm volatile ("ldrex    %0, [%1]\n"
                                          "subs  %0, %0, %2\n"
                                          "strexeq %0, %3, [%1]\n"
                                          : "=&r" (r)
                                          : "r" (&a), "Ir" (o), "r" (n)
                                          : "cc");
                            return (a==1 ? 0 : -1);
                        ]])],
                        [pulseaudio_cv_support_arm_atomic_ops=yes],
                        [pulseaudio_cv_support_arm_atomic_ops=no])
                ])
                AS_IF([test "$pulseaudio_cv_support_arm_atomic_ops" = "yes"], [
                    AC_DEFINE([ATOMIC_ARM_INLINE_ASM], 1, [Have ARM atomic instructions.])
                    need_libatomic_ops=no
                ])
            fi
        ;;
        *-freebsd*)
            AC_MSG_RESULT([yes])
            need_libatomic_ops=no
        ;;
        *)
            AC_MSG_RESULT([unknown])
        ;;
    esac
fi

# If we're on ARM, check for the ARMV6 instructions we need */
case $host in
  arm*)
    AC_CACHE_CHECK([support for required armv6 instructions],
      pulseaudio_cv_support_armv6,
      [AC_COMPILE_IFELSE(
         [AC_LANG_PROGRAM([],
           [[volatile int a = -60000, b = 0xaaaabbbb, c = 0xccccdddd;
             asm volatile ("ldr r0, %2 \n"
                           "ldr r2, %3 \n"
                           "ldr r3, %4 \n"
                           "ssat r1, #8, r0 \n"
                           "str r1, %0 \n"
                           "pkhbt r1, r3, r2, LSL #8 \n"
                           "str r1, %1 \n"
                           : "=m" (a), "=m" (b)
                           : "m" (a), "m" (b), "m" (c)
                           : "r0", "r1", "r2", "r3", "cc");
             return (a == -128 && b == 0xaabbdddd) ? 0 : -1;
           ]])],
         [pulseaudio_cv_support_armv6=yes],
         [pulseaudio_cv_support_armv6=no])
      ])
    AS_IF([test "$pulseaudio_cv_support_armv6" = "yes"], [
        AC_DEFINE([HAVE_ARMV6], 1, [Have ARMv6 instructions.])
      ])
  ;;
  *)
  ;;
esac

#### NEON optimisations ####
AC_ARG_ENABLE([neon-opt],
    AS_HELP_STRING([--enable-neon-opt], [Enable NEON optimisations on ARM CPUs that support it]))

AS_IF([test "x$enable_neon_opt" != "xno"],
    [save_CFLAGS="$CFLAGS"; CFLAGS="-mfpu=neon $CFLAGS"
     AC_COMPILE_IFELSE(
        [AC_LANG_PROGRAM([[#include <arm_neon.h>]], [])],
        [
         HAVE_NEON=1
         NEON_CFLAGS="-mfpu=neon"
        ],
        [
         HAVE_NEON=0
         NEON_CFLAGS=
        ])
     CFLAGS="$save_CFLAGS"
    ],
    [HAVE_NEON=0])

AS_IF([test "x$enable_neon_opt" = "xyes" && test "x$HAVE_NEON" = "x0"],
      [AC_MSG_ERROR([*** Compiler does not support -mfpu=neon or CFLAGS override -mfpu])])

AC_SUBST(HAVE_NEON)
AC_SUBST(NEON_CFLAGS)
AM_CONDITIONAL([HAVE_NEON], [test "x$HAVE_NEON" = x1])
AS_IF([test "x$HAVE_NEON" = "x1"], AC_DEFINE([HAVE_NEON], 1, [Have NEON support?]))


#### libtool stuff ####

LT_PREREQ(2.4)
LT_INIT([dlopen win32-dll disable-static])

dnl As an extra safety device, check for lt_dladvise_init() which is
dnl only implemented in libtool 2.x, and refine as we go if we have
dnl refined requirements.
dnl
dnl Check the header files first since the system may have a
dnl libltdl.so for runtime, but no headers, and we want to bail out as
dnl soon as possible.
dnl
dnl We don't need any special variable for this though, since the user
dnl can give the proper place to find libltdl through the standard
dnl variables like LDFLAGS and CPPFLAGS.

AC_CHECK_HEADER([ltdl.h],
    [AC_CHECK_LIB([ltdl], [lt_dladvise_init], [LIBLTDL=-lltdl], [LIBLTDL=])],
    [LIBLTDL=])

AS_IF([test "x$LIBLTDL" = "x"],
    [AC_MSG_ERROR([Unable to find libltdl version 2. Makes sure you have libtool 2.4 or later installed.])])
AC_SUBST([LIBLTDL])


###################################
#   Basic environment checks      #
###################################

#### Checks for header files. ####

# ISO
AC_HEADER_STDC

# POSIX
AC_CHECK_HEADERS_ONCE([arpa/inet.h cpuid.h glob.h grp.h netdb.h netinet/in.h \
    netinet/in_systm.h netinet/tcp.h poll.h pwd.h sched.h \
    sys/mman.h sys/select.h sys/socket.h sys/wait.h \
    sys/uio.h syslog.h sys/dl.h dlfcn.h linux/sockios.h])
AC_CHECK_HEADERS([netinet/ip.h], [], [],
                 [#include <sys/types.h>
                  #if HAVE_NETINET_IN_H
                  # include <netinet/in.h>
                  #endif
                  #if HAVE_NETINET_IN_SYSTM_H
                  # include <netinet/in_systm.h>
                  #endif
                 ])
AC_CHECK_HEADERS([sys/resource.h], [HAVE_SYS_RESOURCE_H=1], [HAVE_SYS_RESOURCE_H=0])
AC_SUBST(HAVE_SYS_RESOURCE_H)
AC_CHECK_HEADERS([sys/un.h], [HAVE_AF_UNIX=1], [HAVE_AF_UNIX=0])
AM_CONDITIONAL(HAVE_AF_UNIX, test "x$HAVE_AF_UNIX" = "x1")
AC_SUBST(HAVE_AF_UNIX)

# Linux
AC_CHECK_HEADERS([linux/input.h], [HAVE_EVDEV=1], [HAVE_EVDEV=0])
AM_CONDITIONAL([HAVE_EVDEV], [test "x$HAVE_EVDEV" = "x1"])

AC_CHECK_HEADERS_ONCE([sys/prctl.h])

# Solaris
AC_CHECK_HEADERS_ONCE([sys/conf.h sys/filio.h])

# Windows
AC_CHECK_HEADERS_ONCE([windows.h winsock2.h ws2tcpip.h])

# NetBSD
AC_CHECK_HEADERS_ONCE([sys/atomic.h])

# Other
AC_CHECK_HEADERS_ONCE([sys/ioctl.h])
AC_CHECK_HEADERS_ONCE([byteswap.h])
AC_CHECK_HEADERS_ONCE([sys/syscall.h])
AC_CHECK_HEADERS_ONCE([sys/eventfd.h])
AC_CHECK_HEADERS_ONCE([execinfo.h])
AC_CHECK_HEADERS_ONCE([langinfo.h])
AC_CHECK_HEADERS_ONCE([regex.h pcreposix.h])
AC_CHECK_HEADERS_ONCE([locale.h xlocale.h])

AM_CONDITIONAL(HAVE_SYS_EVENTFD_H, test "x$ac_cv_header_sys_eventfd_h" = "xyes")

#### Typdefs, structures, etc. ####

AC_C_CONST
AC_C_BIGENDIAN
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_CHECK_TYPES(ssize_t, , AC_DEFINE([ssize_t], [signed long], [Define ssize_t if it is not done by the standard libs.]))
AC_TYPE_OFF_T

AC_TYPE_UID_T
AC_CHECK_DECLS(environ)

AC_CHECK_SIZEOF(void*)

fast_64bit_operations="no"
# This check covers x32-ABI
AC_CHECK_DECL([__x86_64__], [fast_64bit_operations="yes"], [], [])
if test "x$fast_64bit_operations" = "xno"; then
    AS_IF([test $ac_cv_sizeof_voidp -ge 8], [fast_64bit_operations="yes"])
fi

AS_IF([test "x$fast_64bit_operations" = "xyes"], AC_DEFINE([HAVE_FAST_64BIT_OPERATIONS], 1, [Have CPU with fast 64-bit operations?]))

# SIGXCPU
AX_CHECK_DEFINE([signal.h], [SIGXCPU], [HAVE_SIGXCPU=1], [HAVE_SIGXCPU=0])
AS_IF([test "x$HAVE_SIGXCPU" = "x1"], AC_DEFINE([HAVE_SIGXCPU], 1, [Have SIGXCPU?]))
AM_CONDITIONAL(HAVE_SIGXCPU, test "x$HAVE_SIGXCPU" = "x1")

# INADDR_NONE, Solaris lacks this
AX_CHECK_DEFINE([netinet/in.h], [INADDR_NONE], [],
    [AX_CHECK_DEFINE([winsock2.h], [INADDR_NONE], [],
        [AC_DEFINE([INADDR_NONE],  [0xffffffff], [Define INADDR_NONE if not found in <netinet/in.h>])])])


# _Bool
AC_CACHE_CHECK([whether $CC knows _Bool],
    pulseaudio_cv__Bool,
    [AC_COMPILE_IFELSE(
        [AC_LANG_PROGRAM([], [[_Bool b;]])],
        [pulseaudio_cv__Bool=yes],
        [pulseaudio_cv__Bool=no])
    ])

AS_IF([test "$pulseaudio_cv__Bool" = "yes"], AC_DEFINE([HAVE_STD_BOOL], 1, [Have _Bool.]))


#### Check for libs ####

# ISO
AC_SEARCH_LIBS([pow], [m])

# POSIX
AC_SEARCH_LIBS([sched_setscheduler], [rt])
AC_SEARCH_LIBS([dlopen], [dl])
AC_SEARCH_LIBS([shm_open], [rt])
AC_SEARCH_LIBS([inet_ntop], [nsl])
AC_SEARCH_LIBS([timer_create], [rt])
AC_SEARCH_LIBS([pthread_setaffinity_np], [pthread])
AC_SEARCH_LIBS([pthread_getname_np], [pthread])
AC_SEARCH_LIBS([pthread_setname_np], [pthread])

# BSD
AC_SEARCH_LIBS([connect], [socket])
AC_SEARCH_LIBS([backtrace], [execinfo ubacktrace])

# Darwin/OS X
if test "x$os_is_darwin" = "x1" ; then
    AC_MSG_CHECKING([looking for Apple CoreService Framework])
    AC_CHECK_HEADER([CoreServices/CoreServices.h],
        [LIBS="$LIBS -framework CoreServices"],
        [AC_MSG_ERROR([CoreServices.h header file not found])]
    )

    AC_MSG_RESULT([ok])
    AC_DEFINE([HAVE_CLOCK_GETTIME], 1, [Using clock_gettime() replacement])
    HAVE_BONJOUR=1
fi

AM_CONDITIONAL([HAVE_BONJOUR], [test "x$HAVE_BONJOUR" = x1])

# Windows
AC_SEARCH_LIBS([regexec], [pcreposix])
# This magic is needed so we do not needlessly add static libs to the win32  build, disabling its ability to make dlls.
AC_CHECK_FUNCS([getopt_long], [], [AC_CHECK_LIB([iberty], [getopt_long])])


#### Check for functions ####

# ISO
AC_CHECK_FUNCS_ONCE([lrintf strtof])

# POSIX
AC_FUNC_FORK
AC_FUNC_GETGROUPS
AC_CHECK_FUNCS_ONCE([chmod chown fstat fchown fchmod clock_gettime getaddrinfo getgrgid_r getgrnam_r \
    getpwnam_r getpwuid_r gettimeofday getuid mlock nanosleep \
    pipe posix_fadvise posix_madvise posix_memalign setpgid setsid shm_open \
    sigaction sleep symlink sysconf uname pthread_setaffinity_np pthread_getname_np pthread_setname_np])
AC_CHECK_FUNCS([mkfifo], [HAVE_MKFIFO=1], [HAVE_MKFIFO=0])
AC_SUBST(HAVE_MKFIFO)
AM_CONDITIONAL(HAVE_MKFIFO, test "x$HAVE_MKFIFO" = "x1")

# X/OPEN
AC_CHECK_FUNCS_ONCE([readlink])

# SUSv2
AC_CHECK_FUNCS_ONCE([ctime_r usleep])

# SUSv3
AC_CHECK_FUNCS_ONCE([strerror_r])

# BSD
AC_CHECK_FUNCS_ONCE([lstat paccept])

# Non-standard
AC_CHECK_FUNCS_ONCE([setresuid setresgid setreuid setregid seteuid setegid ppoll strsignal sig2str strtod_l pipe2 accept4])

AC_FUNC_ALLOCA

AC_CHECK_FUNCS([regexec], [HAVE_REGEX=1], [HAVE_REGEX=0])
AM_CONDITIONAL(HAVE_REGEX, [test "x$HAVE_REGEX" = "x1"])

# Large File-Support (LFS)
AC_SYS_LARGEFILE
# Check for open64 to know if the current system does have open64() and similar functions
AC_CHECK_FUNCS_ONCE([open64])

AC_SEARCH_LIBS([dladdr], [dl], [HAVE_DLADDR=1], [HAVE_DLADDR=0])
AC_DEFINE(HAVE_DLADDR, [1], [Have dladdr?])

###################################
#      External libraries         #
###################################

#### [lib]iconv ####

AM_ICONV

#### Linux memfd_create(2) SHM support ####

AC_ARG_ENABLE([memfd],
    AS_HELP_STRING([--disable-memfd], [Disable Linux memfd shared memory]))

AS_IF([test "x$enable_memfd" != "xno"],
    AC_CHECK_DECL(SYS_memfd_create, [HAVE_MEMFD=1], [HAVE_MEMFD=0], [#include <sys/syscall.h>]),
    [HAVE_MEMFD=0])

AS_IF([test "x$enable_memfd" = "xyes" && test "x$HAVE_MEMFD" = "x0"],
    [AC_MSG_ERROR([*** Your Linux kernel does not support memfd shared memory.
                  *** Use linux v3.17 or higher for such a feature.])])

AS_IF([test "x$HAVE_MEMFD" = "x1"],
    AC_CHECK_FUNCS([memfd_create]))

AC_SUBST(HAVE_MEMFD)
AM_CONDITIONAL([HAVE_MEMFD], [test "x$HAVE_MEMFD" = x1])
AS_IF([test "x$HAVE_MEMFD" = "x1"], AC_DEFINE([HAVE_MEMFD], 1, [Have memfd shared memory.]))

#### X11 (optional) ####

AC_ARG_ENABLE([x11],
    AS_HELP_STRING([--disable-x11],[Disable optional X11 support]))

AS_IF([test "x$enable_x11" != "xno"],
    [PKG_CHECK_MODULES(X11, [ x11-xcb xcb >= 1.6 ice sm xtst ], HAVE_X11=1, HAVE_X11=0)],
    HAVE_X11=0)

AS_IF([test "x$enable_x11" = "xyes" && test "x$HAVE_X11" = "x0"],
    [AC_MSG_ERROR([*** X11 not found])])

AC_SUBST(HAVE_X11)
AM_CONDITIONAL([HAVE_X11], [test "x$HAVE_X11" = x1])
AS_IF([test "x$HAVE_X11" = "x1"], AC_DEFINE([HAVE_X11], 1, [Have X11?]))

#### Capabilities (optional) ####

CAP_LIBS=''

AC_ARG_WITH([caps],
    AS_HELP_STRING([--without-caps],[Omit support for dropping capabilities.]))

if test "x${with_caps}" != "xno"; then
    AC_SEARCH_LIBS([cap_init], [cap], [], [])

    # Only give an error on hosts that we know could support capabilities
    AC_CHECK_HEADERS([sys/capability.h], [], [
      if test "${host_has_caps}" = "1"; then
        AC_MSG_ERROR([*** sys/capability.h not found.  Use --without-caps to disable capabilities support.])
      fi])
fi

#### Valgrind (optional) ####

AC_CHECK_HEADERS_ONCE([valgrind/memcheck.h])

#### check unit tests ####

AC_ARG_ENABLE([tests],
    AS_HELP_STRING([--disable-tests],[Disable unit tests]))

AS_IF([test "x$enable_tests" != "xno"],
    [PKG_CHECK_MODULES(LIBCHECK, [ check >= 0.9.10 ], HAVE_LIBCHECK=1, HAVE_LIBCHECK=0)],
    HAVE_LIBCHECK=0)

AS_IF([test "x$enable_tests" = "xyes" && test "x$HAVE_LIBCHECK" = "x0"],
    [AC_MSG_ERROR([*** check library not found or too old])])

AM_CONDITIONAL([HAVE_TESTS], [test "x$HAVE_LIBCHECK" = x1])

#### Sound file ####

PKG_CHECK_MODULES(LIBSNDFILE, [ sndfile >= 1.0.20 ])

#### atomic-ops ####

AC_MSG_CHECKING([whether we need libatomic_ops])
if test "x$need_libatomic_ops" = "xyes"; then
    AC_MSG_RESULT([yes])
    AC_CHECK_HEADERS([atomic_ops.h],
        [CFLAGS="$CFLAGS -DAO_REQUIRE_CAS"],
        [AC_MSG_ERROR([*** libatomic-ops headers not found])])

    # Win32 does not need the lib and breaks horribly if we try to include it
    AS_IF([test "x$os_is_win32" != "x1"], [LIBS="$LIBS -latomic_ops"])
else
    AC_MSG_RESULT([no])
fi

#### Libsamplerate support (optional) ####

AC_ARG_ENABLE([samplerate],
    AS_HELP_STRING([--enable-samplerate],[Enable optional libsamplerate support (DEPRECATED)]))

AS_IF([test "x$enable_samplerate" = "xyes"],
    [PKG_CHECK_MODULES(LIBSAMPLERATE, [ samplerate >= 0.1.0 ], HAVE_LIBSAMPLERATE=1, HAVE_LIBSAMPLERATE=0)],
    HAVE_LIBSAMPLERATE=0)

AS_IF([test "x$enable_samplerate" = "xyes" && test "x$HAVE_LIBSAMPLERATE" = "x0"],
    [AC_MSG_ERROR([*** Libsamplerate not found])])

AM_CONDITIONAL([HAVE_LIBSAMPLERATE], [test "x$HAVE_LIBSAMPLERATE" = x1])
AS_IF([test "x$HAVE_LIBSAMPLERATE" = "x1"], AC_DEFINE([HAVE_LIBSAMPLERATE], 1, [Have libsamplerate?]))

AS_IF([test "x$HAVE_LIBSAMPLERATE" = "x1"], AC_MSG_WARN([Support for libsamplerate is DEPRECATED]))

#### Database support ####

AC_ARG_WITH([database],
    AS_HELP_STRING([--with-database=auto|tdb|gdbm|simple],[Choose database backend.]),[],[with_database=auto])


AS_IF([test "x$with_database" = "xauto" -o "x$with_database" = "xtdb"],
    [PKG_CHECK_MODULES(TDB, [ tdb ], HAVE_TDB=1, HAVE_TDB=0)],
    HAVE_TDB=0)
AS_IF([test "x$HAVE_TDB" = "x1"], with_database=tdb)

AS_IF([test "x$with_database" = "xtdb" && test "x$HAVE_TDB" = "x0"],
    [AC_MSG_ERROR([*** tdb not found])])


AS_IF([test "x$with_database" = "xauto" -o "x$with_database" = "xgdbm"],
    [
        HAVE_GDBM=1
        AC_CHECK_LIB(gdbm, gdbm_open, [], HAVE_GDBM=0)
        AC_CHECK_HEADERS(gdbm.h, [], HAVE_GDBM=0)
    ],
    HAVE_GDBM=0)
AS_IF([test "x$HAVE_GDBM" = "x1"],
    [
        with_database=gdbm
        GDBM_CFLAGS=
        GDBM_LIBS=-lgdbm
    ])

AS_IF([test "x$with_database" = "xgdbm" && test "x$HAVE_GDBM" = "x0"],
    [AC_MSG_ERROR([*** gdbm not found])])


AS_IF([test "x$with_database" = "xauto" -o "x$with_database" = "xsimple"],
    HAVE_SIMPLEDB=1,
    HAVE_SIMPLEDB=0)
AS_IF([test "x$HAVE_SIMPLEDB" = "x1"], with_database=simple)

AS_IF([test "x$HAVE_TDB" != x1 -a "x$HAVE_GDBM" != x1 -a "x$HAVE_SIMPLEDB" != x1],
    AC_MSG_ERROR([*** missing database backend]))


AM_CONDITIONAL([HAVE_TDB], [test "x$HAVE_TDB" = x1])
AS_IF([test "x$HAVE_TDB" = "x1"], AC_DEFINE([HAVE_TDB], 1, [Have tdb?]))

AC_SUBST(GDBM_CFLAGS)
AC_SUBST(GDBM_LIBS)
AM_CONDITIONAL([HAVE_GDBM], [test "x$HAVE_GDBM" = x1])
AS_IF([test "x$HAVE_GDBM" = "x1"], AC_DEFINE([HAVE_GDBM], 1, [Have gdbm?]))

AM_CONDITIONAL([HAVE_SIMPLEDB], [test "x$HAVE_SIMPLEDB" = x1])
AS_IF([test "x$HAVE_SIMPLEDB" = "x1"], AC_DEFINE([HAVE_SIMPLEDB], 1, [Have simple?]))

#### OSS support (optional) ####

AC_ARG_ENABLE([oss-output],
    AS_HELP_STRING([--disable-oss-output],[Disable optional OSS output support]))

AC_ARG_ENABLE([oss-wrapper],
    AS_HELP_STRING([--disable-oss-wrapper],[Disable optional OSS wrapper support]))

AC_ARG_WITH([pulsedsp-location],
    AS_HELP_STRING([--with-pulsedsp-location],[Specify location where OSS wrapper will be installed]))

AS_IF([test "x$enable_oss_output" != "xno" -o "x$enable_oss_wrapper" != "xno"],
    [AC_CHECK_HEADERS([sys/soundcard.h], HAVE_OSS=1, HAVE_OSS=0)],
    HAVE_OSS=0)

AS_IF([test "x$enable_oss_output" = "xyes" -o "x$enable_oss_wrapper" = "xyes" && test "x$HAVE_OSS" = "x0"],
    [AC_MSG_ERROR([*** OSS support not found])])

AS_IF([test "x$enable_oss_output" != "xno"],
    [AS_IF([test "x$HAVE_OSS" = "x1"], HAVE_OSS_OUTPUT=1, HAVE_OSS_OUTPUT=0)],
    HAVE_OSS_OUTPUT=0)

AS_IF([test "x$enable_oss_wrapper" != "xno"],
    [AS_IF([test "x$HAVE_OSS" = "x1"], HAVE_OSS_WRAPPER=1, HAVE_OSS_WRAPPER=0)],
    HAVE_OSS_WRAPPER=0)

AS_IF([test "x$with_pulsedsp_location" != "x"],
    [PULSEDSP_LOCATION="$with_pulsedsp_location"],
    [PULSEDSP_LOCATION="\$(pkglibdir)"])

AC_SUBST(HAVE_OSS_OUTPUT)
AC_SUBST(PULSEDSP_LOCATION)
AM_CONDITIONAL([HAVE_OSS_OUTPUT], [test "x$HAVE_OSS_OUTPUT" = "x1"])
AM_CONDITIONAL([HAVE_OSS_WRAPPER], [test "x$HAVE_OSS_WRAPPER" = "x1"])
AS_IF([test "x$HAVE_OSS_OUTPUT" = "x1"], AC_DEFINE([HAVE_OSS_OUTPUT], 1, [Have OSS output?]))
AS_IF([test "x$HAVE_OSS_WRAPPER" = "x1"], AC_DEFINE([HAVE_OSS_WRAPPER], 1, [Have OSS wrapper (padsp)?]))

# Some platforms like SunOS (Illumos) may ship without SOUND_PCM_* functionality
if test "x$HAVE_OSS" = "x1"; then
    AC_CHECK_DECLS([SOUND_PCM_READ_RATE], [], [], [[#include <sys/soundcard.h>]])
    AC_CHECK_DECLS([SOUND_PCM_READ_CHANNELS], [], [], [[#include <sys/soundcard.h>]])
    AC_CHECK_DECLS([SOUND_PCM_READ_BITS], [], [], [[#include <sys/soundcard.h>]])
fi

#### CoreAudio support (optional) ####

AC_ARG_ENABLE([coreaudio-output],
    AS_HELP_STRING([--disable-coreaudio-output],[Disable optional CoreAudio output support]))

AS_IF([test "x$enable_coreaudio_output" != "xno"],
    [AC_CHECK_HEADERS([CoreAudio/CoreAudio.h], HAVE_COREAUDIO=1, HAVE_COREAUDIO=0)],
    HAVE_COREAUDIO=0)

AS_IF([test "x$enable_coreaudio_output" = "xyes" && test "x$HAVE_COREAUDIO" = "x0"],
    [AC_MSG_ERROR([*** CoreAudio output support not found])])

AC_SUBST(HAVE_COREAUDIO)
AM_CONDITIONAL([HAVE_COREAUDIO], [test "x$HAVE_COREAUDIO" = "x1" && test "x$enable_coreaudio_output" != "xno"])

AS_IF([test "x$HAVE_COREAUDIO" = "x1"], AC_DEFINE([HAVE_COREAUDIO], 1, [Have CoreAudio?]))

#### ALSA support (optional) ####

AC_ARG_ENABLE([alsa],
    AS_HELP_STRING([--disable-alsa],[Disable optional ALSA support]))

AS_IF([test "x$enable_alsa" != "xno"],
    [PKG_CHECK_MODULES(ASOUNDLIB, [ alsa >= 1.0.19 ], HAVE_ALSA=1, HAVE_ALSA=0)],
    HAVE_ALSA=0)

AS_IF([test "x$enable_alsa" = "xyes" && test "x$HAVE_ALSA" = "x0"],
    [AC_MSG_ERROR([*** Needed alsa >= 1.0.19 support not found])])

AS_IF([test "x$HAVE_ALSA" = "x1"],
    [
        save_CPPFLAGS="$CPPFLAGS"; CPPFLAGS="$CPPFLAGS $ASOUNDLIB_CFLAGS"
        AC_CHECK_HEADERS([use-case.h], HAVE_ALSA_UCM=1, HAVE_ALSA_UCM=0)
        CPPFLAGS="$save_CPPFLAGS"
    ],
    HAVE_ALSA_UCM=0)

AC_SUBST(HAVE_ALSA)
AM_CONDITIONAL([HAVE_ALSA], [test "x$HAVE_ALSA" = x1])
AS_IF([test "x$HAVE_ALSA" = "x1"], AC_DEFINE([HAVE_ALSA], 1, [Have ALSA?]))
AS_IF([test "x$HAVE_ALSA_UCM" = "x1"], AC_DEFINE([HAVE_ALSA_UCM], 1, [Have ALSA UCM?]))

#### EsounD support (optional) ####

AC_ARG_ENABLE([esound],
    AS_HELP_STRING([--disable-esound],[Disable optional EsounD support]))
AM_CONDITIONAL([HAVE_ESOUND], [test "x$enable_esound" != "xno"])
AS_IF([test "x$enable_esound" != "xno"], [HAVE_ESOUND=1])

#### Solaris audio support (optional) ####

AC_ARG_ENABLE([solaris],
    AS_HELP_STRING([--disable-solaris],[Disable optional Solaris audio support]))

AS_IF([test "x$enable_solaris" != "xno"],
    [AC_CHECK_HEADERS([sys/audio.h], HAVE_SOLARIS=1, HAVE_SOLARIS=0)],
    HAVE_SOLARIS=0)

AS_IF([test "x$enable_solaris" = "xyes" && test "x$HAVE_SOLARIS" = "x0"],
    [AC_MSG_ERROR([*** Solaris audio support not found])])

AM_CONDITIONAL([HAVE_SOLARIS], [test "x$HAVE_SOLARIS" = x1])
AS_IF([test "x$HAVE_SOLARIS" = "x1"], AC_DEFINE([HAVE_SOLARIS], 1, [Have Solaris audio?]))

#### WaveOut audio support (optional) ####

AC_ARG_ENABLE([waveout],
    AS_HELP_STRING([--disable-waveout],[Disable optional WaveOut audio support]))

AS_IF([test "x$enable_waveout" != "xno"],
    [AC_CHECK_HEADERS([mmsystem.h], HAVE_WAVEOUT=1, HAVE_WAVEOUT=0, [#include <windows.h>])],
    HAVE_WAVEOUT=0)

AS_IF([test "x$enable_waveout" = "xyes" && test "x$HAVE_WAVEOUT" = "x0"],
    [AC_MSG_ERROR([*** WaveOut audio support not found])])

AC_SUBST(HAVE_WAVEOUT)
AM_CONDITIONAL([HAVE_WAVEOUT], [test "x$HAVE_WAVEOUT" = x1])
AS_IF([test "x$HAVE_WAVEOUT" = "x1"], AC_DEFINE([HAVE_WAVEOUT], 1, [Have WaveOut audio?]))

#### GLib 2 support (optional) ####

AC_ARG_ENABLE([glib2],
    AS_HELP_STRING([--disable-glib2],[Disable optional GLib 2 support]))

AS_IF([test "x$enable_glib2" != "xno"],
    [PKG_CHECK_MODULES(GLIB20, [ glib-2.0 >= 2.4.0 ], HAVE_GLIB20=1, HAVE_GLIB20=0)],
    HAVE_GLIB20=0)

AS_IF([test "x$enable_glib2" = "xyes" && test "x$HAVE_GLIB20" = "x0"],
    [AC_MSG_ERROR([*** GLib 2 support not found])])

AC_SUBST(HAVE_GLIB20)
AM_CONDITIONAL([HAVE_GLIB20], [test "x$HAVE_GLIB20" = x1])
AS_IF([test "x$HAVE_GLIB20" = "x1"], AC_DEFINE([HAVE_GLIB], 1, [Have GLIB?]))

#### GTK3 support (optional) ####

AC_ARG_ENABLE([gtk3],
    AS_HELP_STRING([--disable-gtk3],[Disable optional Gtk+ 3 support]))

AS_IF([test "x$enable_gtk3" != "xno"],
    [PKG_CHECK_MODULES(GTK30, [ gtk+-3.0 ], HAVE_GTK30=1, HAVE_GTK30=0)],
    HAVE_GTK30=0)

AS_IF([test "x$enable_gtk3" = "xyes" && test "x$HAVE_GTK30" = "x0"],
    [AC_MSG_ERROR([*** Gtk+ 3 support not found])])

AM_CONDITIONAL([HAVE_GTK30], [test "x$HAVE_GTK30" = x1])
AS_IF([test "x$HAVE_GTK30" = "x1"], AC_DEFINE([HAVE_GTK], 1, [Have GTK?]))

#### GSettings and GConf support (optional) ####

AC_ARG_ENABLE([gsettings],
    AS_HELP_STRING([--disable-gsettings],[Disable optional GSettings support]))

AC_ARG_ENABLE([gconf],
    AS_HELP_STRING([--disable-gconf],[Disable optional GConf support]))

AS_IF([test "x$enable_gsettings" != "xno"],
    [PKG_CHECK_MODULES(GSETTINGS, [ gio-2.0 >= 2.26.0 ], [HAVE_GSETTINGS=1], [HAVE_GSETTINGS=0])],
    HAVE_GSETTINGS=0)

AS_IF([test "x$enable_gsettings" = "xyes" && test "x$HAVE_GSETTINGS" = "x0"],
    [AC_MSG_ERROR([*** GSettings support not found])])

AS_IF([test "x$enable_gconf" != "xno"],
    [PKG_CHECK_MODULES(GCONF, [ gconf-2.0 >= 2.4.0 gobject-2.0 ], HAVE_GCONF=1, HAVE_GCONF=0)],
    HAVE_GCONF=0)

AS_IF([test "x$enable_gconf" = "xyes" && test "x$HAVE_GCONF" = "x0"],
    [AC_MSG_ERROR([*** GConf support not found])])

# Enable only one of GSettings and GConf, unless both were explicitly
# requested. If neither was explicitly requested and both are available, prefer
# GSettings. This is done, because if module-gsettings and module-gconf are
# both loaded, they can cause conflicting or at least confusing configuration.
# Distributions may want to enable both modules when building PulseAudio, if
# they ensure that both modules are never installed at the same time.
AS_IF([test "x$HAVE_GSETTINGS" = "x1" && test "x$enable_gconf" != "xyes"],
      [HAVE_GCONF=0])
AS_IF([test "x$HAVE_GCONF" = "x1" && test "x$enable_gsettings" != "xyes"],
      [HAVE_GSETTINGS=0])

AM_CONDITIONAL([HAVE_GSETTINGS], [test "x$HAVE_GSETTINGS" = "x1"])
AC_SUBST([HAVE_GSETTINGS])
AM_CONDITIONAL([HAVE_GCONF], [test "x$HAVE_GCONF" = "x1"])
AC_SUBST([HAVE_GCONF])

if test "x$HAVE_GSETTINGS" = "x1" ; then
    GLIB_GSETTINGS
fi

#### Avahi support (optional) ####

AC_ARG_ENABLE([avahi],
    AS_HELP_STRING([--disable-avahi],[Disable optional Avahi support]))

AS_IF([test "x$enable_avahi" != "xno"],
    [PKG_CHECK_MODULES(AVAHI, [ avahi-client >= 0.6.0 ], HAVE_AVAHI=1, HAVE_AVAHI=0)],
    HAVE_AVAHI=0)

AS_IF([test "x$enable_avahi" = "xyes" && test "x$HAVE_AVAHI" = "x0"],
    [AC_MSG_ERROR([*** Avahi support not found])])

AC_SUBST(HAVE_AVAHI)
AM_CONDITIONAL([HAVE_AVAHI], [test "x$HAVE_AVAHI" = x1])

#### JACK (optional) ####

AC_ARG_ENABLE([jack],
    AS_HELP_STRING([--disable-jack],[Disable optional JACK support]))

AS_IF([test "x$enable_jack" != "xno"],
    [PKG_CHECK_MODULES(JACK, [ jack >= 0.117.0 ], HAVE_JACK=1, HAVE_JACK=0)],
    HAVE_JACK=0)

AS_IF([test "x$enable_jack" = "xyes" && test "x$HAVE_JACK" = "x0"],
    [AC_MSG_ERROR([*** JACK support not found])])

AM_CONDITIONAL([HAVE_JACK], [test "x$HAVE_JACK" = x1])

#### Async DNS support (optional) ####

AC_ARG_ENABLE([asyncns],
    AS_HELP_STRING([--disable-asyncns],[Disable optional Async DNS support]))

AS_IF([test "x$enable_asyncns" != "xno"],
    [PKG_CHECK_MODULES(LIBASYNCNS, [ libasyncns >= 0.1 ], HAVE_LIBASYNCNS=1, HAVE_LIBASYNCNS=0)],
    HAVE_LIBASYNCNS=0)

AS_IF([test "x$enable_asyncns" = "xyes" && test "x$HAVE_LIBASYNCNS" = "x0"],
    [AC_MSG_ERROR([*** Async DNS support not found])])

AM_CONDITIONAL([HAVE_LIBASYNCNS], [test "x$HAVE_LIBASYNCNS" = x1])
AS_IF([test "x$HAVE_LIBASYNCNS" = "x1"], AC_DEFINE([HAVE_LIBASYNCNS], 1, [Have libasyncns?]))

#### TCP wrappers (optional) ####

AC_ARG_ENABLE([tcpwrap],
    AS_HELP_STRING([--disable-tcpwrap],[Disable optional TCP wrappers support]))

AS_IF([test "x$enable_tcpwrap" != "xno"],
    [
        ACX_LIBWRAP
        AS_IF([test "x$LIBWRAP_LIBS" != "x"], HAVE_TCPWRAP=1, HAVE_TCPWRAP=0)
    ],
    HAVE_TCPWRAP=0)

AS_IF([test "x$enable_tcpwrap" = "xyes" && test "x$HAVE_TCPWRAP" = "x0"],
    [AC_MSG_ERROR([*** TCP wrappers support not found])])

AC_SUBST(LIBWRAP_LIBS)

#### LIRC support (optional) ####

AC_ARG_ENABLE([lirc],
    AS_HELP_STRING([--disable-lirc],[Disable optional LIRC support]))

LIRC_CFLAGS=
LIRC_LIBS=

AS_IF([test "x$enable_lirc" != "xno"],
    [
        HAVE_LIRC=1
        AC_CHECK_HEADER(lirc/lirc_client.h, [], [HAVE_LIRC=0])
        AC_CHECK_LIB(lirc_client, lirc_init, [LIRC_LIBS=-llirc_client], [HAVE_LIRC=0])
    ],
    HAVE_LIRC=0)

AS_IF([test "x$enable_lirc" = "xyes" && test "x$HAVE_LIRC" = "x0"],
    [AC_MSG_ERROR([*** LIRC support not found])])

AC_SUBST(LIRC_CFLAGS)
AC_SUBST(LIRC_LIBS)
AM_CONDITIONAL([HAVE_LIRC], [test "x$HAVE_LIRC" = x1])

#### D-Bus support (optional) ####

AC_ARG_ENABLE([dbus],
    AS_HELP_STRING([--disable-dbus],[Disable optional D-Bus support]))

AS_IF([test "x$enable_dbus" != "xno"],
    [PKG_CHECK_MODULES(DBUS, [ dbus-1 >= 1.4.12 ], HAVE_DBUS=1, HAVE_DBUS=0)],
    HAVE_DBUS=0)

AS_IF([test "x$enable_dbus" = "xyes" && test "x$HAVE_DBUS" = "x0"],
    [AC_MSG_ERROR([*** D-Bus not available or too old version])])

AS_IF([test "x$HAVE_DBUS" = "x1"],
    [
        save_CFLAGS="$CFLAGS"; CFLAGS="$CFLAGS $DBUS_CFLAGS"
        save_LIBS="$LIBS"; LIBS="$LIBS $DBUS_LIBS"
        AC_CHECK_FUNCS(dbus_watch_get_unix_fd)
        CFLAGS="$save_CFLAGS"
        LIBS="$save_LIBS"
    ])

AC_SUBST(HAVE_DBUS)
AM_CONDITIONAL([HAVE_DBUS], [test "x$HAVE_DBUS" = x1])
AS_IF([test "x$HAVE_DBUS" = "x1"], AC_DEFINE([HAVE_DBUS], 1, [Have D-Bus.]))

PA_MACHINE_ID="${sysconfdir}/machine-id"
AX_DEFINE_DIR(PA_MACHINE_ID, PA_MACHINE_ID, [D-Bus machine-id file])
PA_MACHINE_ID_FALLBACK="${localstatedir}/lib/dbus/machine-id"
AX_DEFINE_DIR(PA_MACHINE_ID_FALLBACK, PA_MACHINE_ID_FALLBACK,
	      [Fallback machine-id file])

#### BlueZ support (optional, dependent on D-Bus and SBC) ####

AC_ARG_ENABLE([bluez5],
    AS_HELP_STRING([--disable-bluez5],[Disable optional BlueZ 5 support]))

## SBC ##
AS_IF([test "x$enable_bluez5" != "xno"],
    [PKG_CHECK_MODULES(SBC, [ sbc >= 1.0 ], HAVE_SBC=1, HAVE_SBC=0)],
    HAVE_SBC=0)

## BlueZ 5 ##
AS_IF([test "x$enable_bluez5" != "xno" && test "x$HAVE_DBUS" = "x1" && test "x$HAVE_SBC" = "x1"], HAVE_BLUEZ_5=1,
      HAVE_BLUEZ_5=0)
AS_IF([test "x$enable_bluez5" = "xyes" && test "x$HAVE_BLUEZ_5" != "x1"],
    [AC_MSG_ERROR([*** BLUEZ 5 support not found (requires sbc and D-Bus)])])
AC_SUBST(HAVE_BLUEZ_5)
AM_CONDITIONAL([HAVE_BLUEZ_5], [test "x$HAVE_BLUEZ_5" = x1])

AS_IF([test "x$HAVE_BLUEZ_5" = "x1"], HAVE_BLUEZ=1, HAVE_BLUEZ=0)
AC_SUBST(HAVE_BLUEZ)
AM_CONDITIONAL([HAVE_BLUEZ], [test "x$HAVE_BLUEZ" = x1])

## Bluetooth Headset profiles backend ##

AC_ARG_ENABLE([bluez5-ofono-headset],
    AS_HELP_STRING([--disable-bluez5-ofono-headset],[Disable optional ofono headset backend support (Bluez 5)]))
AS_IF([test "x$HAVE_BLUEZ_5" = "x1" && test "x$enable_bluez5_ofono_headset" != "xno"], HAVE_BLUEZ_5_OFONO_HEADSET=1,
      HAVE_BLUEZ_5_OFONO_HEADSET=0)
AC_SUBST(HAVE_BLUEZ_5_OFONO_HEADSET)
AM_CONDITIONAL([HAVE_BLUEZ_5_OFONO_HEADSET], [test "x$HAVE_BLUEZ_5_OFONO_HEADSET" = x1])
AS_IF([test "x$HAVE_BLUEZ_5_OFONO_HEADSET" = "x1"], AC_DEFINE([HAVE_BLUEZ_5_OFONO_HEADSET], 1, [Bluez 5 ofono headset backend enabled]))

AC_ARG_ENABLE([bluez5-native-headset],
    AS_HELP_STRING([--disable-bluez5-native-headset],[Disable optional native headset backend support (Bluez 5)]))
AS_IF([test "x$HAVE_BLUEZ_5" = "x1" && test "x$enable_bluez5_native_headset" != "xno"],
      [PKG_CHECK_MODULES(BLUEZ, [ bluez >= 4.101 ], HAVE_BLUEZ_5_NATIVE_HEADSET=1, HAVE_BLUEZ_5_NATIVE_HEADSET=0)],
      HAVE_BLUEZ_5_NATIVE_HEADSET=0)
AS_IF([test "x$enable_bluez5_native_headset" = "xyes" && test "x$HAVE_BLUEZ_5_NATIVE_HEADSET" = "x0"],
      [AC_MSG_ERROR([*** BlueZ 5 native headset backend support not available (requires the libbluetooth headers)])])
AC_SUBST(HAVE_BLUEZ_5_NATIVE_HEADSET)
AM_CONDITIONAL([HAVE_BLUEZ_5_NATIVE_HEADSET], [test "x$HAVE_BLUEZ_5_NATIVE_HEADSET" = x1])
AS_IF([test "x$HAVE_BLUEZ_5_NATIVE_HEADSET" = "x1"], AC_DEFINE([HAVE_BLUEZ_5_NATIVE_HEADSET], 1, [Bluez 5 native headset backend enabled]))

#### UDEV support (optional) ####

AC_ARG_ENABLE([udev],
    AS_HELP_STRING([--disable-udev],[Disable optional UDEV support]))

AS_IF([test "x$enable_udev" != "xno" -a \( "x$HAVE_OSS" = "x1" -o "x$HAVE_ALSA" = "x1" \)],
    [PKG_CHECK_MODULES(UDEV, [ libudev >= 143 ], HAVE_UDEV=1, HAVE_UDEV=0)],
    HAVE_UDEV=0)

AS_IF([test "x$enable_udev" = "xyes" && test "x$HAVE_UDEV" = "x0"],
    [AC_MSG_ERROR([*** UDEV support not found])])

AC_SUBST(HAVE_UDEV)
AM_CONDITIONAL([HAVE_UDEV], [test "x$HAVE_UDEV" = x1])
AS_IF([test "x$HAVE_UDEV" = "x1"], AC_DEFINE([HAVE_UDEV], 1, [Have UDEV.]))

#### HAL compat support (optional, dependent on UDEV) ####

AC_ARG_ENABLE([hal-compat],
    AS_HELP_STRING([--disable-hal-compat],[Disable optional HAL->udev transition compatibility support]))

AS_IF([test "x$enable_hal_compat" != "xno"],
    [AS_IF([test "x$HAVE_UDEV" = "x1"], HAVE_HAL_COMPAT=1, HAVE_HAL_COMPAT=0)],
    HAVE_HAL_COMPAT=0)

AM_CONDITIONAL([HAVE_HAL_COMPAT], [test "x$HAVE_HAL_COMPAT" = x1])
AS_IF([test "x$HAVE_HAL_COMPAT" = "x1"], AC_DEFINE([HAVE_HAL_COMPAT], 1, [Have HAL compatibility.]))

#### IPv6 connection support (optional) ####

AC_ARG_ENABLE([ipv6],
    AS_HELP_STRING([--disable-ipv6],[Disable optional IPv6 support]))

AS_IF([test "x$enable_ipv6" != "xno"], [HAVE_IPV6=1], [HAVE_IPV6=0])

AS_IF([test "x$HAVE_IPV6" = "x1"], AC_DEFINE([HAVE_IPV6], 1, [Define this to enable IPv6 connection support]))

#### OpenSSL support (optional) ####

AC_ARG_ENABLE([openssl],
    AS_HELP_STRING([--disable-openssl],[Disable OpenSSL support (used for Airtunes/RAOP)]))

AS_IF([test "x$enable_openssl" != "xno"],
    [PKG_CHECK_MODULES(OPENSSL, [ openssl > 0.9 ], HAVE_OPENSSL=1, HAVE_OPENSSL=0)],
    HAVE_OPENSSL=0)

AS_IF([test "x$enable_openssl" = "xyes" && test "x$HAVE_OPENSSL" = "x0"],
    [AC_MSG_ERROR([*** OpenSSL support not found])])

AM_CONDITIONAL([HAVE_OPENSSL], [test "x$HAVE_OPENSSL" = x1])
AS_IF([test "x$HAVE_OPENSSL" = "x1"], AC_DEFINE([HAVE_OPENSSL], 1, [Have OpenSSL]))

#### FFTW (optional) ####

AC_ARG_WITH([fftw],
    AS_HELP_STRING([--without-fftw],[Omit FFTW-using modules (equalizer)]))

AS_IF([test "x$with_fftw" != "xno"],
    [PKG_CHECK_MODULES(FFTW, [ fftw3f ], HAVE_FFTW=1, HAVE_FFTW=0)],
    HAVE_FFTW=0)

AS_IF([test "x$with_fftw" = "xyes" && test "x$HAVE_FFTW" = "x0"],
    [AC_MSG_ERROR([*** FFTW support not found])])

AM_CONDITIONAL([HAVE_FFTW], [test "x$HAVE_FFTW" = "x1"])

#### speex (optional) ####

AC_ARG_WITH([speex],
    AS_HELP_STRING([--without-speex],[Omit speex (resampling, AEC)]))

AS_IF([test "x$with_speex" != "xno"],
    [PKG_CHECK_MODULES(LIBSPEEX, [ speexdsp >= 1.2 ], HAVE_SPEEX=1, HAVE_SPEEX=0)],
    HAVE_SPEEX=0)

AS_IF([test "x$with_speex" = "xyes" && test "x$HAVE_SPEEX" = "x0"],
    [AC_MSG_ERROR([*** speex support not found])])

AM_CONDITIONAL([HAVE_SPEEX], [test "x$HAVE_SPEEX" = "x1"])
AS_IF([test "x$HAVE_SPEEX" = "x1"], AC_DEFINE([HAVE_SPEEX], 1, [Have speex]))

#### soxr (optional) ####

AC_ARG_WITH([soxr],
    AS_HELP_STRING([--without-soxr],[Omit soxr (resampling)]))

AS_IF([test "x$with_soxr" != "xno"],
    [PKG_CHECK_MODULES(LIBSOXR, [ soxr >= 0.1.1 ], HAVE_SOXR=1, HAVE_SOXR=0)],
    HAVE_SOXR=0)

AS_IF([test "x$with_soxr" = "xyes" && test "x$HAVE_SOXR" = "x0"],
    [AC_MSG_ERROR([*** soxr support not found])])

AM_CONDITIONAL([HAVE_SOXR], [test "x$HAVE_SOXR" = "x1"])
AS_IF([test "x$HAVE_SOXR" = "x1"], AC_DEFINE([HAVE_SOXR], 1, [Have soxr]))


#### gcov support (optional) #####

AC_ARG_ENABLE([gcov],
    AS_HELP_STRING([--enable-gcov],[Enable optional gcov coverage analysis]))

GCOV_CFLAGS=
GCOV_LIBS=" -lgcov"

AS_IF([test "x$enable_gcov" = "xyes"],
    [
        HAVE_GCOV=1
        GCOV_CFLAGS="$GCOV_CFLAGS -fprofile-arcs -ftest-coverage"
        GCOV_LIBS="$GCOV_LIBS -fprofile-arcs"
    ],
    HAVE_GCOV=0)

AC_SUBST(GCOV_CFLAGS)
AC_SUBST(GCOV_LIBS)
AM_CONDITIONAL([HAVE_GCOV], [test "x$HAVE_GCOV" = x1])

#### ORC (optional) ####

ORC_CHECK([0.4.11])

#### systemd support (optional) ####

AC_ARG_ENABLE([systemd-daemon],
    AS_HELP_STRING([--disable-systemd-daemon],[Disable optional systemd daemon (socket activation) support]))

AC_ARG_ENABLE([systemd-login],
    AS_HELP_STRING([--disable-systemd-login],[Disable optional systemd login support]))

AC_ARG_ENABLE([systemd-journal],
    AS_HELP_STRING([--disable-systemd-journal],[Disable optional systemd journal support]))

# Newer systemd's combine their subcomponent libraries into one
# If it exists, we should use it for the further checks

AS_IF([test "x$enable_systemd_daemon" != "xno" || test "x$enable_systemd_login" != "xno" || test "x$enable_systemd_journal" != "xno"],
    [PKG_CHECK_MODULES(SYSTEMD, [ libsystemd ], HAVE_SYSTEMD=1, HAVE_SYSTEMD=0)],
    HAVE_SYSTEMD=0)

AS_IF([test "x$HAVE_SYSTEMD" = "x1"],
    [
        HAVE_SYSTEMD_DAEMON=1
        HAVE_SYSTEMD_LOGIN=1
        HAVE_SYSTEMD_JOURNAL=1
    ])

AC_ARG_WITH([systemduserunitdir],
        AS_HELP_STRING([--with-systemduserunitdir=DIR], [Directory for systemd user service files]),
        [], [with_systemduserunitdir=$($PKG_CONFIG --variable=systemduserunitdir systemd)])
if test "x$with_systemduserunitdir" != xno; then
        AC_SUBST([systemduserunitdir], [$with_systemduserunitdir])
fi

#### systemd daemon support (optional) ####

AS_IF([test "x$enable_systemd_daemon" != "xno"],
    [AS_IF([test "x$HAVE_SYSTEMD_DAEMON" != "x1"], [PKG_CHECK_MODULES(SYSTEMDDAEMON, [ libsystemd-daemon ], HAVE_SYSTEMD_DAEMON=1, HAVE_SYSTEMD_DAEMON=0)])],
    HAVE_SYSTEMD_DAEMON=0)

AS_IF([test "x$enable_systemd_daemon" = "xyes" && test "x$HAVE_SYSTEMD_DAEMON" = "x0"],
    [AC_MSG_ERROR([*** Needed systemd daemon support not found])])

AC_SUBST(HAVE_SYSTEMD_DAEMON)
AM_CONDITIONAL([HAVE_SYSTEMD_DAEMON], [test "x$HAVE_SYSTEMD_DAEMON" = x1])
AS_IF([test "x$HAVE_SYSTEMD_DAEMON" = "x1"], AC_DEFINE([HAVE_SYSTEMD_DAEMON], 1, [Have SYSTEMDDAEMON?]))

#### systemd login support (optional) ####

AS_IF([test "x$enable_systemd_login" != "xno"],
    [AS_IF([test "x$HAVE_SYSTEMD_LOGIN" != "x1"], [PKG_CHECK_MODULES(SYSTEMDLOGIN, [ libsystemd-login ], HAVE_SYSTEMD_LOGIN=1, HAVE_SYSTEMD_LOGIN=0)])],
    HAVE_SYSTEMD_LOGIN=0)

AS_IF([test "x$enable_systemd_login" = "xyes" && test "x$HAVE_SYSTEMD_LOGIN" = "x0"],
    [AC_MSG_ERROR([*** Needed systemd login support not found])])

AC_SUBST(HAVE_SYSTEMD_LOGIN)
AM_CONDITIONAL([HAVE_SYSTEMD_LOGIN], [test "x$HAVE_SYSTEMD_LOGIN" = x1])
AS_IF([test "x$HAVE_SYSTEMD_LOGIN" = "x1"], AC_DEFINE([HAVE_SYSTEMD_LOGIN], 1, [Have SYSTEMDLOGIN?]))

#### systemd journal support (optional) ####

AS_IF([test "x$enable_systemd_journal" != "xno"],
    [AS_IF([test "x$HAVE_SYSTEMD_JOURNAL" != "x1"], [PKG_CHECK_MODULES(SYSTEMDJOURNAL, [ libsystemd-journal ], HAVE_SYSTEMD_JOURNAL=1, HAVE_SYSTEMD_JOURNAL=0)])],
    HAVE_SYSTEMD_JOURNAL=0)

AS_IF([test "x$enable_systemd_journal" = "xyes" && test "x$HAVE_SYSTEMD_JOURNAL" = "x0"],
    [AC_MSG_ERROR([*** Needed systemd journal support not found])])

AC_SUBST(HAVE_SYSTEMD_JOURNAL)
AM_CONDITIONAL([HAVE_SYSTEMD_JOURNAL], [test "x$HAVE_SYSTEMD_JOURNAL" = x1])
AS_IF([test "x$HAVE_SYSTEMD_JOURNAL" = "x1"], AC_DEFINE([HAVE_SYSTEMD_JOURNAL], 1, [Have SYSTEMDJOURNAL?]))

#### Build and Install man pages ####

AC_ARG_ENABLE([manpages],
    AS_HELP_STRING([--disable-manpages],[Disable building and installation of man pages]))

AM_CONDITIONAL([BUILD_MANPAGES], [test "x$enable_manpages" != "xno"])

#### PulseAudio system group & user  #####

AC_ARG_WITH(system_user, AS_HELP_STRING([--with-system-user=<user>],[User for running the PulseAudio daemon as a system-wide instance (pulse)]))
if test -z "$with_system_user" ; then
    PA_SYSTEM_USER=pulse
else
    PA_SYSTEM_USER=$with_system_user
fi
AC_SUBST(PA_SYSTEM_USER)
AC_DEFINE_UNQUOTED(PA_SYSTEM_USER,"$PA_SYSTEM_USER", [User for running the PulseAudio system daemon])

AC_ARG_WITH(system_group,AS_HELP_STRING([--with-system-group=<group>],[Group for running the PulseAudio daemon as a system-wide instance (pulse)]))
if test -z "$with_system_group" ; then
    PA_SYSTEM_GROUP=pulse
else
    PA_SYSTEM_GROUP=$with_system_group
fi
AC_SUBST(PA_SYSTEM_GROUP)
AC_DEFINE_UNQUOTED(PA_SYSTEM_GROUP,"$PA_SYSTEM_GROUP", [Group for the PulseAudio system daemon])

AC_ARG_WITH(access_group,AS_HELP_STRING([--with-access-group=<group>],[Group which is allowed access to a system-wide PulseAudio daemon (pulse-access)]))
if test -z "$with_access_group" ; then
    PA_ACCESS_GROUP=pulse-access
else
    PA_ACCESS_GROUP=$with_access_group
fi
AC_SUBST(PA_ACCESS_GROUP)
AC_DEFINE_UNQUOTED(PA_ACCESS_GROUP,"$PA_ACCESS_GROUP", [Access group])

AC_ARG_ENABLE([per-user-esound-socket],
    AS_HELP_STRING([--disable-per-user-esound-socket],[Use global esound socket directory /tmp/.esd/socket.]))

if test "x$enable_per_user_esound_socket" != "xno"; then
    USE_PER_USER_ESOUND_SOCKET=1
    AC_DEFINE([USE_PER_USER_ESOUND_SOCKET], [1], [Define this if you want per-user esound socket directories])
else
    USE_PER_USER_ESOUND_SOCKET=0
fi

#### PulseAudio system runtime dir ####

PA_SYSTEM_RUNTIME_PATH="${localstatedir}/run/pulse"
AX_DEFINE_DIR(PA_SYSTEM_RUNTIME_PATH, PA_SYSTEM_RUNTIME_PATH, [System runtime dir])
PA_SYSTEM_CONFIG_PATH="${localstatedir}/lib/pulse"
AX_DEFINE_DIR(PA_SYSTEM_CONFIG_PATH, PA_SYSTEM_CONFIG_PATH, [System config dir])
PA_SYSTEM_STATE_PATH="${localstatedir}/lib/pulse"
AX_DEFINE_DIR(PA_SYSTEM_STATE_PATH, PA_SYSTEM_STATE_PATH, [System state dir])

PA_BINARY=${bindir}/pulseaudio${EXEEXT}
AX_DEFINE_DIR(PA_BINARY, PA_BINARY, [Location of pulseaudio binary])

PACTL_BINARY=${bindir}/pactl${EXEEXT}
AX_DEFINE_DIR(PACTL_BINARY, PACTL_BINARY, [Location of pactl binary])

AC_SUBST(PA_SOEXT, [.so])
AC_DEFINE(PA_SOEXT, [".so"], [Shared object extension])

AC_SUBST(pulseconfdir, ["${sysconfdir}/pulse"])
AX_DEFINE_DIR(PA_DEFAULT_CONFIG_DIR, pulseconfdir, [Location of configuration files])

#### Mac OSX specific stuff #####

AC_ARG_ENABLE(mac-universal,
    AS_HELP_STRING([--enable-mac-universal], [Build Mac universal binaries]),
    enable_mac_universal=$enableval, enable_mac_universal="no")

AC_ARG_WITH(mac-version-min,
    AS_HELP_STRING([--with-mac-version-min=<version>], [Defines the earliest version of MacOS X that the executables will run on.]),
    mac_version_min=$withval, mac_version_min="10.5")

AC_ARG_WITH(mac-sysroot,
    AS_HELP_STRING([--with-mac-sysroot=<path>], [SDK basedir to use as the logical root directory for headers and libraries.]),
    mac_sysroot=$withval)

if test "x$os_is_darwin" = "x1" ; then
    LDFLAGS="$LDFLAGS -mmacosx-version-min=$mac_version_min"
    CFLAGS="$CFLAGS -mmacosx-version-min=$mac_version_min"

    if test "x$mac_sysroot" != "x" ; then
        LDFLAGS="$LDFLAGS -isysroot $mac_sysroot"
        CFLAGS="$CFLAGS -isysroot $mac_sysroot"
    fi

    if test "x$enable_mac_universal" = "xyes" ; then
        mac_arches="-arch i386 -arch x86_64"
        LDFLAGS="$LDFLAGS $mac_arches"
        CFLAGS="$CFLAGS $mac_arches"
    fi
fi

AC_ARG_ENABLE([webrtc-aec],
    AS_HELP_STRING([--enable-webrtc-aec], [Enable the optional WebRTC-based echo canceller]))

AS_IF([test "x$enable_webrtc_aec" = "xyes" && test "$HAVE_CXX11" = "0"],
    [AC_MSG_ERROR([*** webrtc-audio-processing needs C++11 support])])

AS_IF([test "x$enable_webrtc_aec" != "xno"],
    [PKG_CHECK_MODULES(WEBRTC, [ webrtc-audio-processing >= 0.2 ], [HAVE_WEBRTC=1], [HAVE_WEBRTC=0])],
    [HAVE_WEBRTC=0])

AS_IF([test "x$enable_webrtc_aec" = "xyes" && test "x$HAVE_WEBRTC" = "x0"],
    [AC_MSG_ERROR([*** webrtc-audio-processing library not found])])

AM_CONDITIONAL([HAVE_WEBRTC], [test "x$HAVE_WEBRTC" = "x1"])

AC_ARG_ENABLE([adrian-aec],
    AS_HELP_STRING([--enable-adrian-aec], [Enable Adrian's optional echo canceller]))
AS_IF([test "x$enable_adrian_aec" != "xno"],
    [HAVE_ADRIAN_EC=1])
AM_CONDITIONAL([HAVE_ADRIAN_EC], [test "x$HAVE_ADRIAN_EC" = "x1"])


#### Thread support ####

AX_TLS
AS_IF([test "$ac_cv_tls" = "__thread"],
    AC_DEFINE([SUPPORT_TLS___THREAD], 1, [Define this if the compiler supports __thread for Thread-Local Storage]))

# Win32 build breaks with win32 pthread installed
AS_IF([test "x$os_is_win32" != "x1"],
  [AX_PTHREAD])

AS_IF([test "x$ax_pthread_ok" = "xyes"],
    AC_DEFINE([_POSIX_PTHREAD_SEMANTICS], 1, [Needed on Solaris]))



###################################
#            Output               #
###################################

AC_DEFINE_UNQUOTED(PA_CFLAGS, "$CFLAGS", [The CFLAGS used during compilation])

# Check whether to build tests by default (as compile-test) or not
AC_ARG_ENABLE([default-build-tests],
    AS_HELP_STRING([--disable-default-build-tests], [Build test programs only during make check]))
AM_CONDITIONAL([BUILD_TESTS_DEFAULT], [test "x$enable_default_build_tests" != "xno"])

AC_ARG_ENABLE([legacy-database-entry-format],
        AS_HELP_STRING([--disable-legacy-database-entry-format], [Try to load legacy (< 1.0) database files (card, device and volume restore).]))
if test "x$enable_legacy_database_entry_format" != "xno" ; then
        AC_DEFINE(ENABLE_LEGACY_DATABASE_ENTRY_FORMAT, [1], [Legacy database entry format])
fi

AC_ARG_ENABLE([static-bins],
    AS_HELP_STRING([--enable-static-bins],[Statically link executables.]))
AM_CONDITIONAL([STATIC_BINS], [test "x$enable_static_bins" = "xyes"])

AC_ARG_WITH(
        [preopen-mods],
        AS_HELP_STRING([--with-preopen-mods],[Modules to preopen in daemon (default: all).]),
        [PREOPEN_MODS=$withval], [PREOPEN_MODS="all"])
AM_CONDITIONAL([PREOPEN_MODS], [test "x$PREOPEN_MODS" != "xall"])
if test "x$PREOPEN_MODS" != "xall" ; then
    tmpLIBS=""
    for mod in $PREOPEN_MODS; do
        tmpLIBS="$tmpLIBS module-$mod.la"
    done
    PREOPEN_MODS="$tmpLIBS"
    AC_SUBST(PREOPEN_MODS)
fi

AC_ARG_WITH(
        [module-dir],
        AS_HELP_STRING([--with-module-dir],[Directory where to install the modules to (defaults to ${libdir}/pulse-${PA_MAJORMINOR}/modules]),
        [modlibexecdir=$withval], [modlibexecdir="${libdir}/pulse-${PA_MAJORMINOR}/modules"])

AC_SUBST(modlibexecdir)
AX_DEFINE_DIR(PA_DLSEARCHPATH, modlibexecdir, [Modules dir])

AC_ARG_WITH(
        [udev-rules-dir],
        AS_HELP_STRING([--with-udev-rules-dir],[Directory where to install udev rules to (defaults to /lib/udev/rules.d)]),
        [udevrulesdir=$withval], [udevrulesdir="/lib/udev/rules.d"])

AC_SUBST(udevrulesdir)

AC_ARG_WITH([bash-completion-dir],
        AS_HELP_STRING([--with-bash-completion-dir=DIR], [Directory for bash completion files]),
        [bashcompletiondir=$withval], [bashcompletiondir=$($PKG_CONFIG --variable=completionsdir bash-completion)])
if test "x$bashcompletionsdir" = "x"; then
	bashcompletiondir="${datadir}/bash-completion/completions"
fi

AC_SUBST(bashcompletiondir)

AC_ARG_WITH(
        [zsh-completion-dir],
        AS_HELP_STRING([--with-zsh-completion-dir], [Zsh completions directory (defaults to ${datadir}/zsh/site-functions)]),
        [zshcompletiondir=$withval], [zshcompletiondir="${datadir}/zsh/site-functions"])

AC_SUBST(zshcompletiondir)

AC_ARG_ENABLE([force-preopen],
    AS_HELP_STRING([--enable-force-preopen],[Preopen modules, even when dlopen() is supported.]))

if test "x$enable_force_preopen" = "xyes"; then
    FORCE_PREOPEN=yes
else
    FORCE_PREOPEN=no
fi

AM_CONDITIONAL([FORCE_PREOPEN], [test "x$FORCE_PREOPEN" = "xyes"])

AC_CONFIG_FILES([
Makefile
src/Makefile
man/Makefile
libpulse.pc
libpulse-simple.pc
libpulse-mainloop-glib.pc
doxygen/Makefile
doxygen/doxygen.conf
src/pulse/version.h
po/Makefile.in
man/pulseaudio.1.xml
man/pax11publish.1.xml
man/pacat.1.xml
man/pacmd.1.xml
man/pactl.1.xml
man/pasuspender.1.xml
man/padsp.1.xml
man/pulse-daemon.conf.5.xml
man/pulse-client.conf.5.xml
man/default.pa.5.xml
man/pulse-cli-syntax.5.xml
man/start-pulseaudio-x11.1.xml
])

AS_IF([test "x$HAVE_ESOUND" = "x1"],
    [
        AC_CONFIG_FILES([man/esdcompat.1.xml])
        AC_CONFIG_FILES([src/esdcompat:src/daemon/esdcompat.in], [chmod +x src/esdcompat])
    ])

AC_CONFIG_FILES([src/start-pulseaudio-x11:src/daemon/start-pulseaudio-x11.in], [chmod +x src/start-pulseaudio-x11])
AC_CONFIG_FILES([src/client.conf:src/pulse/client.conf.in])
AC_CONFIG_FILES([src/daemon.conf:src/daemon/daemon.conf.in],
    [m4 src/daemon.conf > src/daemon.conf.gen && mv src/daemon.conf.gen src/daemon.conf])
AC_CONFIG_FILES([src/default.pa:src/daemon/default.pa.in],
    [m4 src/default.pa > src/default.pa.gen && mv src/default.pa.gen src/default.pa])
AC_CONFIG_FILES([src/system.pa:src/daemon/system.pa.in],
    [m4 src/system.pa > src/system.pa.gen && mv src/system.pa.gen src/system.pa])
AS_IF([test "x$HAVE_SYSTEMD_DAEMON" = "x1"],
    [
        AC_CONFIG_FILES([src/pulseaudio.service:src/daemon/systemd/user/pulseaudio.service.in])
    ])

# CMake related ProjectConfig files
PA_LIBDIR="$libdir"
AX_DEFINE_DIR(PA_LIBDIR, PA_LIBDIR, [PulseAudio library dir])
PA_INCDIR="$includedir"
AX_DEFINE_DIR(PA_INCDIR, PA_INCDIR, [PulseAudio include dir])

AC_CONFIG_FILES([PulseAudioConfig.cmake:PulseAudioConfig.cmake.in],
    [m4 PulseAudioConfig.cmake > PulseAudioConfig.cmake.gen && mv PulseAudioConfig.cmake.gen PulseAudioConfig.cmake])
AC_CONFIG_FILES([PulseAudioConfigVersion.cmake])

AC_OUTPUT

# ==========================================================================

AS_IF([test "x$HAVE_MEMFD" = "x1"], ENABLE_MEMFD=yes, ENABLE_MEMFD=no)
AS_IF([test "x$HAVE_X11" = "x1"], ENABLE_X11=yes, ENABLE_X11=no)
AS_IF([test "x$HAVE_OSS_OUTPUT" = "x1"], ENABLE_OSS_OUTPUT=yes, ENABLE_OSS_OUTPUT=no)
AS_IF([test "x$HAVE_OSS_WRAPPER" = "x1"], ENABLE_OSS_WRAPPER=yes, ENABLE_OSS_WRAPPER=no)
AS_IF([test "x$HAVE_ALSA" = "x1"], ENABLE_ALSA=yes, ENABLE_ALSA=no)
AS_IF([test "x$HAVE_COREAUDIO" = "x1"], ENABLE_COREAUDIO=yes, ENABLE_COREAUDIO=no)
AS_IF([test "x$HAVE_SOLARIS" = "x1"], ENABLE_SOLARIS=yes, ENABLE_SOLARIS=no)
AS_IF([test "x$HAVE_WAVEOUT" = "x1"], ENABLE_WAVEOUT=yes, ENABLE_WAVEOUT=no)
AS_IF([test "x$HAVE_GLIB20" = "x1"], ENABLE_GLIB20=yes, ENABLE_GLIB20=no)
AS_IF([test "x$HAVE_GTK30" = "x1"], ENABLE_GTK30=yes, ENABLE_GTK30=no)
AS_IF([test "x$HAVE_GCONF" = "x1"], ENABLE_GCONF=yes, ENABLE_GCONF=no)
AS_IF([test "x$HAVE_GSETTINGS" = "x1"], ENABLE_GSETTINGS=yes, ENABLE_GSETTINGS=no)
AS_IF([test "x$HAVE_AVAHI" = "x1"], ENABLE_AVAHI=yes, ENABLE_AVAHI=no)
AS_IF([test "x$HAVE_JACK" = "x1"], ENABLE_JACK=yes, ENABLE_JACK=no)
AS_IF([test "x$HAVE_LIBASYNCNS" = "x1"], ENABLE_LIBASYNCNS=yes, ENABLE_LIBASYNCNS=no)
AS_IF([test "x$HAVE_LIRC" = "x1"], ENABLE_LIRC=yes, ENABLE_LIRC=no)
AS_IF([test "x$HAVE_DBUS" = "x1"], ENABLE_DBUS=yes, ENABLE_DBUS=no)
AS_IF([test "x$HAVE_UDEV" = "x1"], ENABLE_UDEV=yes, ENABLE_UDEV=no)
AS_IF([test "x$HAVE_SYSTEMD_DAEMON" = "x1"], ENABLE_SYSTEMD_DAEMON=yes, ENABLE_SYSTEMD_DAEMON=no)
AS_IF([test "x$HAVE_SYSTEMD_LOGIN" = "x1"], ENABLE_SYSTEMD_LOGIN=yes, ENABLE_SYSTEMD_LOGIN=no)
AS_IF([test "x$HAVE_SYSTEMD_JOURNAL" = "x1"], ENABLE_SYSTEMD_JOURNAL=yes, ENABLE_SYSTEMD_JOURNAL=no)
AS_IF([test "x$HAVE_BLUEZ_5" = "x1"], ENABLE_BLUEZ_5=yes, ENABLE_BLUEZ_5=no)
AS_IF([test "x$HAVE_BLUEZ_5_OFONO_HEADSET" = "x1"], ENABLE_BLUEZ_5_OFONO_HEADSET=yes, ENABLE_BLUEZ_5_OFONO_HEADSET=no)
AS_IF([test "x$HAVE_BLUEZ_5_NATIVE_HEADSET" = "x1"], ENABLE_BLUEZ_5_NATIVE_HEADSET=yes, ENABLE_BLUEZ_5_NATIVE_HEADSET=no)
AS_IF([test "x$HAVE_HAL_COMPAT" = "x1"], ENABLE_HAL_COMPAT=yes, ENABLE_HAL_COMPAT=no)
AS_IF([test "x$HAVE_TCPWRAP" = "x1"], ENABLE_TCPWRAP=yes, ENABLE_TCPWRAP=no)
AS_IF([test "x$HAVE_LIBSAMPLERATE" = "x1"], ENABLE_LIBSAMPLERATE="yes (DEPRECATED)", ENABLE_LIBSAMPLERATE=no)
AS_IF([test "x$HAVE_IPV6" = "x1"], ENABLE_IPV6=yes, ENABLE_IPV6=no)
AS_IF([test "x$HAVE_OPENSSL" = "x1"], ENABLE_OPENSSL=yes, ENABLE_OPENSSL=no)
AS_IF([test "x$HAVE_FFTW" = "x1"], ENABLE_FFTW=yes, ENABLE_FFTW=no)
AS_IF([test "x$HAVE_ORC" = "xyes"], ENABLE_ORC=yes, ENABLE_ORC=no)
AS_IF([test "x$HAVE_ADRIAN_EC" = "x1"], ENABLE_ADRIAN_EC=yes, ENABLE_ADRIAN_EC=no)
AS_IF([test "x$HAVE_SPEEX" = "x1"], ENABLE_SPEEX=yes, ENABLE_SPEEX=no)
AS_IF([test "x$HAVE_SOXR" = "x1"], ENABLE_SOXR=yes, ENABLE_SOXR=no)
AS_IF([test "x$HAVE_WEBRTC" = "x1"], ENABLE_WEBRTC=yes, ENABLE_WEBRTC=no)
AS_IF([test "x$HAVE_TDB" = "x1"], ENABLE_TDB=yes, ENABLE_TDB=no)
AS_IF([test "x$HAVE_GDBM" = "x1"], ENABLE_GDBM=yes, ENABLE_GDBM=no)
AS_IF([test "x$HAVE_SIMPLEDB" = "x1"], ENABLE_SIMPLEDB=yes, ENABLE_SIMPLEDB=no)
AS_IF([test "x$HAVE_ESOUND" = "x1"], ENABLE_ESOUND=yes, ENABLE_ESOUND=no)
AS_IF([test "x$HAVE_ESOUND" = "x1" -a "x$USE_PER_USER_ESOUND_SOCKET" = "x1"], ENABLE_PER_USER_ESOUND_SOCKET=yes, ENABLE_PER_USER_ESOUND_SOCKET=no)
AS_IF([test "x$HAVE_GCOV" = "x1"], ENABLE_GCOV=yes, ENABLE_GCOV=no)
AS_IF([test "x$HAVE_LIBCHECK" = "x1"], ENABLE_TESTS=yes, ENABLE_TESTS=no)
AS_IF([test "x$enable_legacy_database_entry_format" != "xno"], ENABLE_LEGACY_DATABASE_ENTRY_FORMAT=yes, ENABLE_LEGACY_DATABASE_ENTRY_FORMAT=no)

echo "
 ---{ $PACKAGE_NAME $VERSION }---

    prefix:                        ${prefix}
    sysconfdir:                    ${sysconfdir}
    localstatedir:                 ${localstatedir}
    modlibexecdir:                 ${modlibexecdir}
    System Runtime Path:           ${PA_SYSTEM_RUNTIME_PATH}
    System State Path:             ${PA_SYSTEM_STATE_PATH}
    System Config Path:            ${PA_SYSTEM_CONFIG_PATH}
    Zsh completions directory:     ${zshcompletiondir}
    Bash completions directory:    ${bashcompletiondir}
    Compiler:                      ${CC}
    CFLAGS:                        ${CFLAGS}
    CPPFLAGS:                      ${CPPFLAGS}
    LIBS:                          ${LIBS}

    Enable memfd shared memory:    ${ENABLE_MEMFD}
    Enable X11:                    ${ENABLE_X11}
    Enable OSS Output:             ${ENABLE_OSS_OUTPUT}
    Enable OSS Wrapper:            ${ENABLE_OSS_WRAPPER}
    Enable EsounD:                 ${ENABLE_ESOUND}
    Enable Alsa:                   ${ENABLE_ALSA}
    Enable CoreAudio:              ${ENABLE_COREAUDIO}
    Enable Solaris:                ${ENABLE_SOLARIS}
    Enable WaveOut:                ${ENABLE_WAVEOUT}
    Enable GLib 2.0:               ${ENABLE_GLIB20}
    Enable Gtk+ 3.0:               ${ENABLE_GTK30}
    Enable GConf:                  ${ENABLE_GCONF}
    Enable GSettings:              ${ENABLE_GSETTINGS}
    Enable Avahi:                  ${ENABLE_AVAHI}
    Enable Jack:                   ${ENABLE_JACK}
    Enable Async DNS:              ${ENABLE_LIBASYNCNS}
    Enable LIRC:                   ${ENABLE_LIRC}
    Enable D-Bus:                  ${ENABLE_DBUS}
      Enable BlueZ 5:              ${ENABLE_BLUEZ_5}
        Enable ofono headsets:     ${ENABLE_BLUEZ_5_OFONO_HEADSET}
        Enable native headsets:    ${ENABLE_BLUEZ_5_NATIVE_HEADSET}
    Enable udev:                   ${ENABLE_UDEV}
      Enable HAL->udev compat:     ${ENABLE_HAL_COMPAT}
    Enable systemd
      Daemon (Socket Activation):  ${ENABLE_SYSTEMD_DAEMON}
      Login (Session Tracking):    ${ENABLE_SYSTEMD_LOGIN}
      Journal (Logging):           ${ENABLE_SYSTEMD_JOURNAL}
    Enable TCP Wrappers:           ${ENABLE_TCPWRAP}
    Enable libsamplerate:          ${ENABLE_LIBSAMPLERATE}
    Enable IPv6:                   ${ENABLE_IPV6}
    Enable OpenSSL (for Airtunes): ${ENABLE_OPENSSL}
    Enable fftw:                   ${ENABLE_FFTW}
    Enable orc:                    ${ENABLE_ORC}
    Enable Adrian echo canceller:  ${ENABLE_ADRIAN_EC}
    Enable speex (resampler, AEC): ${ENABLE_SPEEX}
    Enable soxr (resampler):       ${ENABLE_SOXR}
    Enable WebRTC echo canceller:  ${ENABLE_WEBRTC}
    Enable gcov coverage:          ${ENABLE_GCOV}
    Enable unit tests:             ${ENABLE_TESTS}
    Database
      tdb:                         ${ENABLE_TDB}
      gdbm:                        ${ENABLE_GDBM}
      simple database:             ${ENABLE_SIMPLEDB}

    System User:                   ${PA_SYSTEM_USER}
    System Group:                  ${PA_SYSTEM_GROUP}
    Access Group:                  ${PA_ACCESS_GROUP}
    Enable per-user EsounD socket: ${ENABLE_PER_USER_ESOUND_SOCKET}
    Force preopen:                 ${FORCE_PREOPEN}
    Preopened modules:             ${PREOPEN_MODS}

    Legacy Database Entry Support: ${ENABLE_LEGACY_DATABASE_ENTRY_FORMAT}
"

if test "${ENABLE_SPEEX}" = "no" && test "${ENABLE_WEBRTC}" = "no" && test "${ENABLE_ADRIAN_EC}" = "no" ; then
AC_MSG_ERROR([At least one echo canceller implementation must be available.])
fi

if test "${ENABLE_DBUS}" = "no" && test "x$os_is_win32" != "x1" ; then
   echo "
===== WARNING WARNING WARNING WARNING WARNING WARNING WARNING =====
You do not have D-Bus support enabled. It is strongly recommended
that you enable D-Bus support if your platform supports it.
Many parts of PulseAudio use D-Bus, from ConsoleKit interaction
to the Device Reservation Protocol to speak to JACK, Bluetooth
support and even a native control protocol for communicating and
controling the PulseAudio daemon itself.
===== WARNING WARNING WARNING WARNING WARNING WARNING WARNING =====
"
fi

if test "${ENABLE_UDEV}" = "no" && test "x$os_is_win32" != "x1" ; then
   echo "
===== WARNING WARNING WARNING WARNING WARNING WARNING WARNING =====
You do not have udev support enabled. It is strongly recommended
that you enable udev support if your platform supports it as it is
the primary method used to detect hardware audio devices (on Linux)
and is thus a critical part of PulseAudio on that platform.
===== WARNING WARNING WARNING WARNING WARNING WARNING WARNING =====
"
fi

if test "${ENABLE_SPEEX}" = "no" && test "x$os_is_win32" != "x1" ; then
   echo "
===== WARNING WARNING WARNING WARNING WARNING WARNING WARNING =====
You do not have speex support enabled. It is strongly recommended
that you enable speex support if your platform supports it as it is
the primary method used for audio resampling and is thus a critical
part of PulseAudio on that platform.
===== WARNING WARNING WARNING WARNING WARNING WARNING WARNING =====
"
fi

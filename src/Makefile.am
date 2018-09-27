# This file is part of PulseAudio.
#
# Copyright 2004-2006 Lennart Poettering
# Copyright 2006 Pierre Ossman <ossman@cendio.se> for Cendio AB
# Copyright 2006 Diego Pettenò
#
# PulseAudio is free software; you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published by
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

###################################
#       Extra directories         #
###################################

pulseincludedir=$(includedir)/pulse
pulsecoreincludedir=$(includedir)/pulsecore
pulselibexecdir=$(libexecdir)/pulse
if HAVE_X11
xdgautostartdir=$(sysconfdir)/xdg/autostart
endif
if HAVE_ALSA
alsaprofilesetsdir=$(datadir)/pulseaudio/alsa-mixer/profile-sets
alsapathsdir=$(datadir)/pulseaudio/alsa-mixer/paths
endif
if HAVE_DBUS
dbuspolicydir=$(sysconfdir)/dbus-1/system.d
endif
if HAVE_GSETTINGS
gsettingsdataconvertdir=$(datadir)/GConf/gsettings
endif

###################################
#     Compiler/linker flags       #
###################################

AM_CPPFLAGS = \
	-I$(top_srcdir)/src \
	-I$(top_srcdir)/src/modules \
	-I$(top_builddir)/src/modules \
	-DPA_ALSA_PATHS_DIR=\"$(alsapathsdir)\" \
	-DPA_ALSA_PROFILE_SETS_DIR=\"$(alsaprofilesetsdir)\" \
	-DPA_SRCDIR=\"$(abs_srcdir)\" \
	-DPA_BUILDDIR=\"$(abs_builddir)\" \
	-DPULSE_LOCALEDIR=\"$(localedir)\"
AM_CFLAGS = -std=gnu11 \
	$(PTHREAD_CFLAGS)
AM_CXXFLAGS = -std=c++11 \
	$(PTHREAD_CFLAGS)
SERVER_CFLAGS = -D__INCLUDED_FROM_PULSE_AUDIO

AM_LIBADD = $(PTHREAD_LIBS) $(INTLLIBS)
AM_LDADD = $(PTHREAD_LIBS) $(INTLLIBS)
AM_LDFLAGS =
# Should only be applied to libraries.
AM_LIBLDFLAGS = $(NODELETE_LDFLAGS)

if HAVE_GCOV
AM_CFLAGS+=$(GCOV_CFLAGS)
AM_CXXFLAGS+=$(GCOV_CFLAGS)
AM_LDFLAGS+=$(GCOV_LIBS)
endif

if STATIC_BINS
BINLDFLAGS = -static
endif

if OS_IS_WIN32
AM_LDFLAGS+=-Wl,--export-all-symbols,--enable-auto-import -no-undefined
WINSOCK_LIBS=-lwsock32 -lws2_32 -lwininet
endif

if OS_IS_DARWIN
AM_LDFLAGS+=-Wl,-headerpad_max_install_names -headerpad_max_install_names
endif

FOREIGN_CFLAGS = -w

MODULE_LDFLAGS = $(AM_LDFLAGS) $(AM_LIBLDFLAGS) -module -disable-static -avoid-version $(NOUNDEFINED_LDFLAGS)
MODULE_LIBADD = $(AM_LIBADD) libpulsecore-@PA_MAJORMINOR@.la libpulsecommon-@PA_MAJORMINOR@.la libpulse.la

###################################
#          Extra files            #
###################################

EXTRA_DIST = \
		pulse/client.conf.in \
		pulse/version.h.in \
		pulsecore/filter/LICENSE.WEBKIT \
		daemon/daemon.conf.in \
		daemon/default.pa.in \
		daemon/system.pa.in \
		depmod.py \
		daemon/esdcompat.in \
		daemon/start-pulseaudio-x11.in \
		daemon/systemd/user/pulseaudio.service.in \
		daemon/systemd/user/pulseaudio.socket \
		utils/padsp.in \
		utils/qpaeq \
		daemon/pulseaudio.desktop.in \
		map-file \
		daemon/pulseaudio-system.conf \
		modules/echo-cancel/adrian-license.txt \
		modules/gsettings/org.freedesktop.pulseaudio.gschema.xml \
		modules/gsettings/pulseaudio.convert

pulseconf_DATA = \
		default.pa \
		system.pa \
		daemon.conf \
		client.conf

if HAVE_DBUS
dbuspolicy_DATA = \
		daemon/pulseaudio-system.conf
endif

if HAVE_X11
xdgautostart_in_files = \
		daemon/pulseaudio.desktop.in
xdgautostart_DATA = $(xdgautostart_in_files:.desktop.in=.desktop)
$(xdgautostart_DATA): $(xdgautostart_in_files)
	$(AM_V_GEN) $(MSGFMT) --desktop --template $< -d $(top_srcdir)/po -o $@

endif


###################################
#          Includes               #
###################################

BUILT_SOURCES =
CLEANFILES =
include $(top_srcdir)/orc.mak
ORC_SOURCE =

###################################
#          Main daemon            #
###################################

bin_PROGRAMS = pulseaudio

pulseaudio_SOURCES = \
		daemon/caps.c daemon/caps.h \
		daemon/cmdline.c daemon/cmdline.h \
		daemon/cpulimit.c daemon/cpulimit.h \
		daemon/daemon-conf.c daemon/daemon-conf.h \
		daemon/dumpmodules.c daemon/dumpmodules.h \
		daemon/ltdl-bind-now.c daemon/ltdl-bind-now.h \
		daemon/main.c

pulseaudio_CFLAGS = $(AM_CFLAGS) $(CAP_CFLAGS)
pulseaudio_LDADD = $(AM_LDADD) libpulsecore-@PA_MAJORMINOR@.la libpulsecommon-@PA_MAJORMINOR@.la libpulse.la $(LIBLTDL) $(CAP_LIBS)
# This is needed because automake doesn't properly expand the foreach below
pulseaudio_DEPENDENCIES = libpulsecore-@PA_MAJORMINOR@.la libpulsecommon-@PA_MAJORMINOR@.la libpulse.la $(PREOPEN_LIBS)

if HAVE_DBUS
pulseaudio_CFLAGS += $(DBUS_CFLAGS)
pulseaudio_SOURCES += daemon/server-lookup.c daemon/server-lookup.h
pulseaudio_LDADD += $(DBUS_LIBS)
endif

if PREOPEN_MODS
PREOPEN_LIBS = $(PREOPEN_MODS)
else
PREOPEN_LIBS = $(modlibexec_LTLIBRARIES)
endif

if FORCE_PREOPEN
pulseaudio_LDFLAGS = $(AM_LDFLAGS) $(BINLDFLAGS) $(IMMEDIATE_LDFLAGS) -dlpreopen force $(foreach f,$(PREOPEN_LIBS),-dlpreopen $(f))
else
pulseaudio_LDFLAGS = $(AM_LDFLAGS) $(BINLDFLAGS) $(IMMEDIATE_LDFLAGS) -dlopen force $(foreach f,$(PREOPEN_LIBS),-dlopen $(f))
endif

if HAVE_SYSTEMD_DAEMON
pulseaudio_CFLAGS += $(SYSTEMD_FLAGS) $(SYSTEMDDAEMON_FLAGS)
pulseaudio_LDFLAGS += $(SYSTEMD_LIBS) $(SYSTEMDDAEMON_LIBS)
endif

###################################
#       Utility programs          #
###################################

bin_SCRIPTS =

if HAVE_ESOUND
bin_SCRIPTS += esdcompat
endif

bin_PROGRAMS += \
		pacat \
		pactl

if !OS_IS_WIN32
bin_PROGRAMS += pasuspender
endif

if HAVE_AF_UNIX
bin_PROGRAMS += pacmd
endif

if HAVE_X11
bin_PROGRAMS += pax11publish
bin_SCRIPTS += start-pulseaudio-x11
endif

pacat_SOURCES = utils/pacat.c
pacat_LDADD = $(AM_LDADD) libpulse.la libpulsecommon-@PA_MAJORMINOR@.la $(LIBSNDFILE_LIBS)
pacat_CFLAGS = $(AM_CFLAGS) $(LIBSNDFILE_CFLAGS)
pacat_LDFLAGS = $(AM_LDFLAGS) $(BINLDFLAGS)

pactl_SOURCES = utils/pactl.c
pactl_LDADD = $(AM_LDADD) libpulse.la libpulsecommon-@PA_MAJORMINOR@.la $(LIBSNDFILE_LIBS)
pactl_CFLAGS = $(AM_CFLAGS) $(LIBSNDFILE_CFLAGS)
pactl_LDFLAGS = $(AM_LDFLAGS) $(BINLDFLAGS)

pasuspender_SOURCES = utils/pasuspender.c
pasuspender_LDADD = $(AM_LDADD) libpulse.la libpulsecommon-@PA_MAJORMINOR@.la
pasuspender_CFLAGS = $(AM_CFLAGS)
pasuspender_LDFLAGS = $(AM_LDFLAGS) $(BINLDFLAGS)

pacmd_SOURCES = utils/pacmd.c
pacmd_CFLAGS = $(AM_CFLAGS)
pacmd_LDADD = $(AM_LDADD) libpulse.la libpulsecommon-@PA_MAJORMINOR@.la
pacmd_LDFLAGS = $(AM_LDFLAGS) $(BINLDFLAGS)

pax11publish_SOURCES = utils/pax11publish.c
pax11publish_CFLAGS = $(AM_CFLAGS) $(X11_CFLAGS)
pax11publish_LDADD = $(AM_LDADD) libpulse.la libpulsecommon-@PA_MAJORMINOR@.la $(X11_LIBS)
pax11publish_LDFLAGS = $(AM_LDFLAGS) $(BINLDFLAGS)

if HAVE_SYSTEMD_DAEMON

systemduserunit_DATA = \
    pulseaudio.service \
    daemon/systemd/user/pulseaudio.socket

endif

###################################
#         Test programs           #
###################################
noinst_LTLIBRARIES =

TESTS_default = \
		core-util-test \
		mainloop-test \
		strlist-test \
		close-test \
		memblockq-test \
		channelmap-test \
		thread-mainloop-test \
		utf8-test \
		format-test \
		json-test \
		get-binary-name-test \
		hook-list-test \
		memblock-test \
		asyncq-test \
		asyncmsgq-test \
		queue-test \
		rtpoll-test \
		resampler-test \
		smoother-test \
		thread-test \
		volume-test \
		mix-test \
		proplist-test \
		cpu-mix-test \
		cpu-remap-test \
		cpu-sconv-test \
		cpu-volume-test \
		lock-autospawn-test \
		mult-s16-test \
		lfe-filter-test

TESTS_norun = \
		ipacl-test \
		mcalign-test \
		pacat-simple \
		parec-simple \
		flist-test \
		remix-test \
		rtstutter \
		sig2str-test \
		stripnul \
		echo-cancel-test \
		lo-latency-test

# These tests need a running pulseaudio daemon
TESTS_daemon = \
		connect-stress \
		extended-test \
		interpol-test \
		sync-playback

if !OS_IS_WIN32
TESTS_default += \
		sigbus-test \
		usergroup-test
endif

if HAVE_SYS_EVENTFD_H
TESTS_default += \
		srbchannel-test
endif

if !OS_IS_DARWIN
TESTS_default += \
		once-test
endif

if HAVE_SIGXCPU
TESTS_norun += \
		cpulimit-test \
		cpulimit-test2
endif

if HAVE_GLIB20
TESTS_default += \
		mainloop-test-glib

if HAVE_GTK30
# gtk-test depends on both glib and gtk
TESTS_norun += \
		gtk-test
endif
endif

if HAVE_ALSA
TESTS_norun += \
		alsa-time-test
TESTS_default += \
		alsa-mixer-path-test
endif

if HAVE_TESTS
TESTS_ENVIRONMENT=MAKE_CHECK=1
TESTS = $(TESTS_default)

if BUILD_TESTS_DEFAULT
noinst_PROGRAMS = $(TESTS_default) $(TESTS_norun) $(TESTS_daemon)
else
check_PROGRAMS = $(TESTS_default) $(TESTS_norun)
endif

check-daemon: $(TESTS_daemon)
	PATH=$(builddir):${PATH} $(top_srcdir)/src/tests/test-daemon.sh $(TESTS_daemon)

else
TESTS_ENVIRONMENT=
TESTS =
noinst_PROGRAMS =
check_PROGRAMS =

check-daemon:
	@echo "Tests are disabled!"
	@echo "Pass option \"--enable-tests\" to configure and install \"check\" library properly!"
	false

endif

core_util_test_SOURCES = tests/core-util-test.c
core_util_test_CFLAGS = $(AM_CFLAGS) $(LIBCHECK_CFLAGS)
core_util_test_LDADD = $(AM_LDADD) libpulse.la libpulsecommon-@PA_MAJORMINOR@.la
core_util_test_LDFLAGS = $(AM_LDFLAGS) $(BINLDFLAGS) $(LIBCHECK_LIBS)

mainloop_test_SOURCES = tests/mainloop-test.c
mainloop_test_CFLAGS = $(AM_CFLAGS) $(LIBCHECK_CFLAGS)
mainloop_test_LDADD = $(AM_LDADD) libpulse.la libpulsecommon-@PA_MAJORMINOR@.la
mainloop_test_LDFLAGS = $(AM_LDFLAGS) $(BINLDFLAGS) $(LIBCHECK_LIBS)

thread_mainloop_test_SOURCES = tests/thread-mainloop-test.c
thread_mainloop_test_CFLAGS = $(AM_CFLAGS) $(LIBCHECK_CFLAGS)
thread_mainloop_test_LDADD = $(AM_LDADD) libpulsecore-@PA_MAJORMINOR@.la libpulse.la libpulsecommon-@PA_MAJORMINOR@.la
thread_mainloop_test_LDFLAGS = $(AM_LDFLAGS) $(BINLDFLAGS) $(LIBCHECK_LIBS)

utf8_test_SOURCES = tests/utf8-test.c
utf8_test_CFLAGS = $(AM_CFLAGS) $(LIBCHECK_CFLAGS)
utf8_test_LDADD = $(AM_LDADD) libpulse.la libpulsecommon-@PA_MAJORMINOR@.la
utf8_test_LDFLAGS = $(AM_LDFLAGS) $(BINLDFLAGS) $(LIBCHECK_LIBS)

format_test_SOURCES = tests/format-test.c
format_test_CFLAGS = $(AM_CFLAGS) $(LIBCHECK_CFLAGS)
format_test_LDADD = $(AM_LDADD) libpulsecore-@PA_MAJORMINOR@.la libpulse.la libpulsecommon-@PA_MAJORMINOR@.la
format_test_LDFLAGS = $(AM_LDFLAGS) $(BINLDFLAGS) $(LIBCHECK_LIBS)

json_test_SOURCES = tests/json-test.c
json_test_CFLAGS = $(AM_CFLAGS) $(LIBCHECK_CFLAGS)
json_test_LDADD = $(AM_LDADD) libpulse.la libpulsecommon-@PA_MAJORMINOR@.la
json_test_LDFLAGS = $(AM_LDFLAGS) $(BINLDFLAGS) $(LIBCHECK_LIBS)

srbchannel_test_SOURCES = tests/srbchannel-test.c
srbchannel_test_CFLAGS = $(AM_CFLAGS) $(LIBCHECK_CFLAGS)
srbchannel_test_LDADD = $(AM_LDADD) libpulse.la libpulsecommon-@PA_MAJORMINOR@.la
srbchannel_test_LDFLAGS = $(AM_LDFLAGS) $(BINLDFLAGS) $(LIBCHECK_LIBS)

get_binary_name_test_SOURCES = tests/get-binary-name-test.c
get_binary_name_test_CFLAGS = $(AM_CFLAGS) $(LIBCHECK_CFLAGS)
get_binary_name_test_LDADD = $(AM_LDADD) libpulse.la libpulsecommon-@PA_MAJORMINOR@.la
get_binary_name_test_LDFLAGS = $(AM_LDFLAGS) $(BINLDFLAGS) $(LIBCHECK_LIBS)

ipacl_test_SOURCES = tests/ipacl-test.c
ipacl_test_CFLAGS = $(AM_CFLAGS) $(LIBCHECK_CFLAGS)
ipacl_test_LDADD = $(AM_LDADD) libpulsecore-@PA_MAJORMINOR@.la libpulse.la libpulsecommon-@PA_MAJORMINOR@.la
ipacl_test_LDFLAGS = $(AM_LDFLAGS) $(BINLDFLAGS) $(LIBCHECK_LIBS)

hook_list_test_SOURCES = tests/hook-list-test.c
hook_list_test_CFLAGS = $(AM_CFLAGS) $(LIBCHECK_CFLAGS)
hook_list_test_LDADD = $(AM_LDADD) libpulsecore-@PA_MAJORMINOR@.la libpulse.la libpulsecommon-@PA_MAJORMINOR@.la
hook_list_test_LDFLAGS = $(AM_LDFLAGS) $(BINLDFLAGS) $(LIBCHECK_LIBS)

memblock_test_SOURCES = tests/memblock-test.c
memblock_test_CFLAGS = $(AM_CFLAGS) $(LIBCHECK_CFLAGS)
memblock_test_LDADD = $(AM_LDADD) libpulsecore-@PA_MAJORMINOR@.la libpulse.la libpulsecommon-@PA_MAJORMINOR@.la
memblock_test_LDFLAGS = $(AM_LDFLAGS) $(BINLDFLAGS) $(LIBCHECK_LIBS)

thread_test_SOURCES = tests/thread-test.c
thread_test_CFLAGS = $(AM_CFLAGS) $(LIBCHECK_CFLAGS)
thread_test_LDADD = $(AM_LDADD) libpulsecore-@PA_MAJORMINOR@.la libpulse.la libpulsecommon-@PA_MAJORMINOR@.la
thread_test_LDFLAGS = $(AM_LDFLAGS) $(BINLDFLAGS) $(LIBCHECK_LIBS)

once_test_SOURCES = tests/once-test.c
once_test_CFLAGS = $(AM_CFLAGS) $(LIBCHECK_CFLAGS)
once_test_LDADD = $(AM_LDADD) libpulsecore-@PA_MAJORMINOR@.la libpulse.la libpulsecommon-@PA_MAJORMINOR@.la
once_test_LDFLAGS = $(AM_LDFLAGS) $(BINLDFLAGS) $(LIBCHECK_LIBS)

flist_test_SOURCES = tests/flist-test.c
flist_test_CFLAGS = $(AM_CFLAGS)
flist_test_LDADD = $(AM_LDADD) libpulsecore-@PA_MAJORMINOR@.la libpulse.la libpulsecommon-@PA_MAJORMINOR@.la
flist_test_LDFLAGS = $(AM_LDFLAGS) $(BINLDFLAGS)

asyncq_test_SOURCES = tests/asyncq-test.c
asyncq_test_CFLAGS = $(AM_CFLAGS) $(LIBCHECK_CFLAGS)
asyncq_test_LDADD = $(AM_LDADD) libpulsecore-@PA_MAJORMINOR@.la libpulse.la libpulsecommon-@PA_MAJORMINOR@.la
asyncq_test_LDFLAGS = $(AM_LDFLAGS) $(BINLDFLAGS) $(LIBCHECK_LIBS)

asyncmsgq_test_SOURCES = tests/asyncmsgq-test.c
asyncmsgq_test_CFLAGS = $(AM_CFLAGS) $(LIBCHECK_CFLAGS)
asyncmsgq_test_LDADD = $(AM_LDADD) libpulsecore-@PA_MAJORMINOR@.la libpulse.la libpulsecommon-@PA_MAJORMINOR@.la
asyncmsgq_test_LDFLAGS = $(AM_LDFLAGS) $(BINLDFLAGS) $(LIBCHECK_LIBS)

queue_test_SOURCES = tests/queue-test.c
queue_test_CFLAGS = $(AM_CFLAGS) $(LIBCHECK_CFLAGS)
queue_test_LDADD = $(AM_LDADD) libpulsecore-@PA_MAJORMINOR@.la libpulse.la libpulsecommon-@PA_MAJORMINOR@.la
queue_test_LDFLAGS = $(AM_LDFLAGS) $(BINLDFLAGS) $(LIBCHECK_LIBS)

rtpoll_test_SOURCES = tests/rtpoll-test.c
rtpoll_test_CFLAGS = $(AM_CFLAGS) $(LIBCHECK_CFLAGS)
rtpoll_test_LDADD = $(AM_LDADD) libpulsecore-@PA_MAJORMINOR@.la libpulse.la libpulsecommon-@PA_MAJORMINOR@.la
rtpoll_test_LDFLAGS = $(AM_LDFLAGS) $(BINLDFLAGS) $(LIBCHECK_LIBS)

mcalign_test_SOURCES = tests/mcalign-test.c
mcalign_test_CFLAGS = $(AM_CFLAGS)
mcalign_test_LDADD = $(AM_LDADD) $(WINSOCK_LIBS) libpulsecore-@PA_MAJORMINOR@.la libpulse.la libpulsecommon-@PA_MAJORMINOR@.la
mcalign_test_LDFLAGS = $(AM_LDFLAGS) $(BINLDFLAGS)

pacat_simple_SOURCES = tests/pacat-simple.c
pacat_simple_LDADD = $(AM_LDADD) libpulse.la libpulse-simple.la
pacat_simple_CFLAGS = $(AM_CFLAGS)
pacat_simple_LDFLAGS = $(AM_LDFLAGS) $(BINLDFLAGS)

parec_simple_SOURCES = tests/parec-simple.c
parec_simple_LDADD = $(AM_LDADD) libpulse.la libpulse-simple.la
parec_simple_CFLAGS = $(AM_CFLAGS)
parec_simple_LDFLAGS = $(AM_LDFLAGS) $(BINLDFLAGS)

extended_test_SOURCES = tests/extended-test.c
extended_test_LDADD = $(AM_LDADD) libpulse.la
extended_test_CFLAGS = $(AM_CFLAGS) $(LIBCHECK_CFLAGS)
extended_test_LDFLAGS = $(AM_LDFLAGS) $(BINLDFLAGS) $(LIBCHECK_LIBS)

strlist_test_SOURCES = tests/strlist-test.c
strlist_test_CFLAGS = $(AM_CFLAGS) $(LIBCHECK_CFLAGS)
strlist_test_LDADD = $(AM_LDADD) $(WINSOCK_LIBS) libpulsecore-@PA_MAJORMINOR@.la libpulse.la libpulsecommon-@PA_MAJORMINOR@.la
strlist_test_LDFLAGS = $(AM_LDFLAGS) $(BINLDFLAGS) $(LIBCHECK_LIBS)

close_test_SOURCES = tests/close-test.c
close_test_CFLAGS = $(AM_CFLAGS)
close_test_LDADD = $(AM_LDADD) $(WINSOCK_LIBS) libpulsecore-@PA_MAJORMINOR@.la libpulse.la libpulsecommon-@PA_MAJORMINOR@.la
close_test_LDFLAGS = $(AM_LDFLAGS) $(BINLDFLAGS)

volume_test_SOURCES = tests/volume-test.c
volume_test_CFLAGS = $(AM_CFLAGS) $(LIBCHECK_CFLAGS)
volume_test_LDADD = $(AM_LDADD) libpulse.la libpulsecommon-@PA_MAJORMINOR@.la
volume_test_LDFLAGS = $(AM_LDFLAGS) $(BINLDFLAGS) $(LIBCHECK_LIBS)

channelmap_test_SOURCES = tests/channelmap-test.c
channelmap_test_CFLAGS = $(AM_CFLAGS) $(LIBCHECK_CFLAGS)
channelmap_test_LDADD = $(AM_LDADD) libpulse.la
channelmap_test_LDFLAGS = $(AM_LDFLAGS) $(BINLDFLAGS) $(LIBCHECK_LIBS)

cpulimit_test_SOURCES = tests/cpulimit-test.c daemon/cpulimit.c daemon/cpulimit.h
cpulimit_test_CFLAGS = $(AM_CFLAGS) $(LIBCHECK_CFLAGS)
cpulimit_test_LDADD = $(AM_LDADD) libpulsecore-@PA_MAJORMINOR@.la libpulse.la libpulsecommon-@PA_MAJORMINOR@.la
cpulimit_test_LDFLAGS = $(AM_LDFLAGS) $(BINLDFLAGS) $(LIBCHECK_LIBS)

cpulimit_test2_SOURCES = tests/cpulimit-test.c daemon/cpulimit.c daemon/cpulimit.h
cpulimit_test2_CFLAGS = $(AM_CFLAGS) -DTEST2 $(LIBCHECK_CFLAGS)
cpulimit_test2_LDADD = $(AM_LDADD) libpulsecore-@PA_MAJORMINOR@.la libpulse.la libpulsecommon-@PA_MAJORMINOR@.la
cpulimit_test2_LDFLAGS = $(AM_LDFLAGS) $(BINLDFLAGS) $(LIBCHECK_LIBS)

mainloop_test_glib_SOURCES = $(mainloop_test_SOURCES)
mainloop_test_glib_CFLAGS = $(mainloop_test_CFLAGS) $(LIBCHECK_CFLAGS) $(GLIB20_CFLAGS) -DGLIB_MAIN_LOOP
mainloop_test_glib_LDADD = $(mainloop_test_LDADD) $(GLIB20_LIBS) libpulse-mainloop-glib.la
mainloop_test_glib_LDFLAGS = $(AM_LDFLAGS) $(BINLDFLAGS) $(LIBCHECK_LIBS)

memblockq_test_SOURCES = tests/memblockq-test.c
memblockq_test_CFLAGS = $(AM_CFLAGS) $(LIBCHECK_CFLAGS)
memblockq_test_LDADD = $(AM_LDADD) $(WINSOCK_LIBS) libpulsecore-@PA_MAJORMINOR@.la libpulse.la libpulsecommon-@PA_MAJORMINOR@.la
memblockq_test_LDFLAGS = $(AM_LDFLAGS) $(BINLDFLAGS) $(LIBCHECK_LIBS)

sync_playback_SOURCES = tests/sync-playback.c
sync_playback_LDADD = $(AM_LDADD) libpulse.la
sync_playback_CFLAGS = $(AM_CFLAGS) $(LIBCHECK_CFLAGS)
sync_playback_LDFLAGS = $(AM_LDFLAGS) $(BINLDFLAGS) $(LIBCHECK_LIBS)

interpol_test_SOURCES = tests/interpol-test.c
interpol_test_LDADD = $(AM_LDADD) libpulsecore-@PA_MAJORMINOR@.la libpulse.la libpulsecommon-@PA_MAJORMINOR@.la
interpol_test_CFLAGS = $(AM_CFLAGS) $(LIBCHECK_CFLAGS)
interpol_test_LDFLAGS = $(AM_LDFLAGS) $(BINLDFLAGS) $(LIBCHECK_LIBS)

sig2str_test_SOURCES = tests/sig2str-test.c
sig2str_test_LDADD = $(AM_LDADD) libpulsecore-@PA_MAJORMINOR@.la libpulse.la libpulsecommon-@PA_MAJORMINOR@.la
sig2str_test_CFLAGS = $(AM_CFLAGS) $(LIBCHECK_CFLAGS)
sig2str_test_LDFLAGS = $(AM_LDFLAGS) $(BINLDFLAGS) $(LIBCHECK_LIBS)

resampler_test_SOURCES = tests/resampler-test.c
resampler_test_LDADD = $(AM_LDADD) libpulsecore-@PA_MAJORMINOR@.la libpulse.la libpulsecommon-@PA_MAJORMINOR@.la
resampler_test_CFLAGS = $(AM_CFLAGS)
resampler_test_LDFLAGS = $(AM_LDFLAGS) $(BINLDFLAGS)

mix_test_SOURCES = tests/mix-test.c
mix_test_LDADD = $(AM_LDADD) libpulsecore-@PA_MAJORMINOR@.la libpulse.la libpulsecommon-@PA_MAJORMINOR@.la
mix_test_CFLAGS = $(AM_CFLAGS) $(LIBCHECK_CFLAGS)
mix_test_LDFLAGS = $(AM_LDFLAGS) $(BINLDFLAGS) $(LIBCHECK_LIBS)

remix_test_SOURCES = tests/remix-test.c
remix_test_LDADD = $(AM_LDADD) libpulsecore-@PA_MAJORMINOR@.la libpulse.la libpulsecommon-@PA_MAJORMINOR@.la
remix_test_CFLAGS = $(AM_CFLAGS)
remix_test_LDFLAGS = $(AM_LDFLAGS) $(BINLDFLAGS)

smoother_test_SOURCES = tests/smoother-test.c
smoother_test_LDADD = $(AM_LDADD) libpulsecore-@PA_MAJORMINOR@.la libpulse.la libpulsecommon-@PA_MAJORMINOR@.la
smoother_test_CFLAGS = $(AM_CFLAGS) $(LIBCHECK_CFLAGS)
smoother_test_LDFLAGS = $(AM_LDFLAGS) $(BINLDFLAGS) $(LIBCHECK_LIBS)

proplist_test_SOURCES = tests/proplist-test.c
proplist_test_LDADD = $(AM_LDADD) libpulsecore-@PA_MAJORMINOR@.la libpulse.la libpulsecommon-@PA_MAJORMINOR@.la
proplist_test_CFLAGS = $(AM_CFLAGS) $(LIBCHECK_CFLAGS)
proplist_test_LDFLAGS = $(AM_LDFLAGS) $(BINLDFLAGS) $(LIBCHECK_LIBS)

cpu_mix_test_SOURCES = tests/cpu-mix-test.c tests/runtime-test-util.h
cpu_mix_test_LDADD = $(AM_LDADD) libpulsecore-@PA_MAJORMINOR@.la libpulse.la libpulsecommon-@PA_MAJORMINOR@.la
cpu_mix_test_CFLAGS = $(AM_CFLAGS) $(LIBCHECK_CFLAGS)
cpu_mix_test_LDFLAGS = $(AM_LDFLAGS) $(BINLDFLAGS) $(LIBCHECK_LIBS)

cpu_remap_test_SOURCES = tests/cpu-remap-test.c tests/runtime-test-util.h
cpu_remap_test_LDADD = $(AM_LDADD) libpulsecore-@PA_MAJORMINOR@.la libpulse.la libpulsecommon-@PA_MAJORMINOR@.la
cpu_remap_test_CFLAGS = $(AM_CFLAGS) $(LIBCHECK_CFLAGS)
cpu_remap_test_LDFLAGS = $(AM_LDFLAGS) $(BINLDFLAGS) $(LIBCHECK_LIBS)

cpu_sconv_test_SOURCES = tests/cpu-sconv-test.c tests/runtime-test-util.h
cpu_sconv_test_LDADD = $(AM_LDADD) libpulsecore-@PA_MAJORMINOR@.la libpulse.la libpulsecommon-@PA_MAJORMINOR@.la
cpu_sconv_test_CFLAGS = $(AM_CFLAGS) $(LIBCHECK_CFLAGS)
cpu_sconv_test_LDFLAGS = $(AM_LDFLAGS) $(BINLDFLAGS) $(LIBCHECK_LIBS)

cpu_volume_test_SOURCES = tests/cpu-volume-test.c tests/runtime-test-util.h
cpu_volume_test_LDADD = $(AM_LDADD) libpulsecore-@PA_MAJORMINOR@.la libpulse.la libpulsecommon-@PA_MAJORMINOR@.la
cpu_volume_test_CFLAGS = $(AM_CFLAGS) $(LIBCHECK_CFLAGS)
cpu_volume_test_LDFLAGS = $(AM_LDFLAGS) $(BINLDFLAGS) $(LIBCHECK_LIBS)

mult_s16_test_SOURCES = tests/mult-s16-test.c tests/runtime-test-util.h
mult_s16_test_LDADD = $(AM_LDADD) libpulsecore-@PA_MAJORMINOR@.la libpulse.la libpulsecommon-@PA_MAJORMINOR@.la
mult_s16_test_CFLAGS = $(AM_CFLAGS) $(LIBCHECK_CFLAGS)
mult_s16_test_LDFLAGS = $(AM_LDFLAGS) $(BINLDFLAGS) $(LIBCHECK_LIBS)

lfe_filter_test_SOURCES = tests/lfe-filter-test.c
lfe_filter_test_LDADD = $(AM_LDADD) libpulsecore-@PA_MAJORMINOR@.la libpulse.la libpulsecommon-@PA_MAJORMINOR@.la
lfe_filter_test_CFLAGS = $(AM_CFLAGS) $(LIBCHECK_CFLAGS)
lfe_filter_test_LDFLAGS = $(AM_LDFLAGS) $(BINLDFLAGS) $(LIBCHECK_LIBS)

rtstutter_SOURCES = tests/rtstutter.c
rtstutter_LDADD = $(AM_LDADD) libpulsecore-@PA_MAJORMINOR@.la libpulse.la libpulsecommon-@PA_MAJORMINOR@.la
rtstutter_CFLAGS = $(AM_CFLAGS)
rtstutter_LDFLAGS = $(AM_LDFLAGS) $(BINLDFLAGS)

stripnul_SOURCES = tests/stripnul.c
stripnul_LDADD = $(AM_LDADD) libpulsecore-@PA_MAJORMINOR@.la libpulse.la libpulsecommon-@PA_MAJORMINOR@.la
stripnul_CFLAGS = $(AM_CFLAGS)
stripnul_LDFLAGS = $(AM_LDFLAGS) $(BINLDFLAGS)

lock_autospawn_test_SOURCES = tests/lock-autospawn-test.c
lock_autospawn_test_LDADD = $(AM_LDADD) libpulsecore-@PA_MAJORMINOR@.la libpulse.la libpulsecommon-@PA_MAJORMINOR@.la
lock_autospawn_test_CFLAGS = $(AM_CFLAGS) $(LIBCHECK_CFLAGS)
lock_autospawn_test_LDFLAGS = $(AM_LDFLAGS) $(BINLDFLAGS) $(LIBCHECK_LIBS)

sigbus_test_SOURCES = tests/sigbus-test.c
sigbus_test_LDADD = $(AM_LDADD) libpulsecore-@PA_MAJORMINOR@.la libpulse.la libpulsecommon-@PA_MAJORMINOR@.la
sigbus_test_CFLAGS = $(AM_CFLAGS) $(LIBCHECK_CFLAGS)
sigbus_test_LDFLAGS = $(AM_LDFLAGS) $(BINLDFLAGS) $(LIBCHECK_LIBS)

gtk_test_SOURCES = tests/gtk-test.c
gtk_test_LDADD = $(AM_LDADD) $(GTK30_LIBS) libpulse-mainloop-glib.la libpulse.la
gtk_test_CFLAGS = $(AM_CFLAGS) $(GTK30_CFLAGS)
gtk_test_LDFLAGS = $(AM_LDFLAGS) $(BINLDFLAGS)

alsa_time_test_SOURCES = tests/alsa-time-test.c
alsa_time_test_LDADD = $(AM_LDADD) $(ASOUNDLIB_LIBS)
alsa_time_test_CFLAGS = $(AM_CFLAGS) $(ASOUNDLIB_CFLAGS)
alsa_time_test_LDFLAGS = $(AM_LDFLAGS) $(BINLDFLAGS)

alsa_mixer_path_test_SOURCES = tests/alsa-mixer-path-test.c
alsa_mixer_path_test_CFLAGS = $(AM_CFLAGS) $(LIBCHECK_CFLAGS) $(ASOUNDLIB_CFLAGS)
alsa_mixer_path_test_LDADD = $(AM_LDADD) libpulsecore-@PA_MAJORMINOR@.la libpulse.la libpulsecommon-@PA_MAJORMINOR@.la libalsa-util.la
alsa_mixer_path_test_LDFLAGS = $(AM_LDFLAGS) $(BINLDFLAGS) $(LIBCHECK_LIBS)

usergroup_test_SOURCES = tests/usergroup-test.c
usergroup_test_LDADD = $(AM_LDADD) libpulsecore-@PA_MAJORMINOR@.la libpulse.la libpulsecommon-@PA_MAJORMINOR@.la
usergroup_test_CFLAGS = $(AM_CFLAGS) $(LIBCHECK_CFLAGS)
usergroup_test_LDFLAGS = $(AM_LDFLAGS) $(BINLDFLAGS) $(LIBCHECK_LIBS)

connect_stress_SOURCES = tests/connect-stress.c
connect_stress_LDADD = $(AM_LDADD) libpulse.la
connect_stress_CFLAGS = $(AM_CFLAGS) $(LIBCHECK_CFLAGS)
connect_stress_LDFLAGS = $(AM_LDFLAGS) $(BINLDFLAGS) $(LIBCHECK_LIBS)

echo_cancel_test_SOURCES = $(module_echo_cancel_la_SOURCES)
nodist_echo_cancel_test_SOURCES = $(nodist_module_echo_cancel_la_SOURCES)
echo_cancel_test_LDADD = $(module_echo_cancel_la_LIBADD)
echo_cancel_test_CFLAGS = $(module_echo_cancel_la_CFLAGS) -DECHO_CANCEL_TEST=1
if HAVE_WEBRTC
echo_cancel_test_CXXFLAGS = $(module_echo_cancel_la_CXXFLAGS) -DECHO_CANCEL_TEST=1
endif
echo_cancel_test_LDFLAGS = $(AM_LDFLAGS) $(BINLDFLAGS)

liblo_test_util_la_SOURCES = tests/lo-test-util.h tests/lo-test-util.c
liblo_test_util_la_LIBADD = libpulsecore-@PA_MAJORMINOR@.la
liblo_test_util_la_LDFLAGS = -avoid-version
noinst_LTLIBRARIES += liblo-test-util.la

lo_latency_test_SOURCES = tests/lo-latency-test.c
lo_latency_test_LDADD = $(AM_LDADD) libpulse.la liblo-test-util.la
lo_latency_test_CFLAGS = $(AM_CFLAGS) $(LIBCHECK_CFLAGS)
lo_latency_test_LDFLAGS = $(AM_LDFLAGS) $(BINLDFLAGS) $(LIBCHECK_LIBS)

###################################
#         Common library          #
###################################

commonlibdir = $(pkglibdir)
commonlib_LTLIBRARIES = \
		libpulsecommon-@PA_MAJORMINOR@.la

# We duplicate files from pulse/ in this to allow as-needed linking. If we did
# not do this, in situations where code in libpulsecommon uses code in
# libpulse, we would then need to link libpulsecommon to libpulse (in addition
# to the existing libpulse being linked to libpulsecommon). Duplicating the
# code allows us to prevent this circular linking.
libpulsecommon_@PA_MAJORMINOR@_la_SOURCES = \
		pulse/client-conf.c pulse/client-conf.h \
		pulse/fork-detect.c pulse/fork-detect.h \
		pulse/format.c pulse/format.h \
		pulse/json.c pulse/json.h \
		pulse/xmalloc.c pulse/xmalloc.h \
		pulse/proplist.c pulse/proplist.h \
		pulse/utf8.c pulse/utf8.h \
		pulse/channelmap.c pulse/channelmap.h \
		pulse/sample.c pulse/sample.h \
		pulse/util.c pulse/util.h \
		pulse/timeval.c pulse/timeval.h \
		pulse/rtclock.c pulse/rtclock.h \
		pulse/volume.c pulse/volume.h \
		pulsecore/atomic.h \
		pulsecore/authkey.c pulsecore/authkey.h \
		pulsecore/conf-parser.c pulsecore/conf-parser.h \
		pulsecore/core-error.c pulsecore/core-error.h \
		pulsecore/core-format.c pulsecore/core-format.h \
		pulsecore/core-rtclock.c pulsecore/core-rtclock.h \
		pulsecore/core-util.c pulsecore/core-util.h \
		pulsecore/creds.h \
		pulsecore/dynarray.c pulsecore/dynarray.h \
		pulsecore/endianmacros.h \
		pulsecore/fdsem.c pulsecore/fdsem.h \
		pulsecore/flist.c pulsecore/flist.h \
		pulsecore/g711.c pulsecore/g711.h \
		pulsecore/hashmap.c pulsecore/hashmap.h \
		pulsecore/i18n.c pulsecore/i18n.h \
		pulsecore/idxset.c pulsecore/idxset.h \
		pulsecore/arpa-inet.c pulsecore/arpa-inet.h \
		pulsecore/iochannel.c pulsecore/iochannel.h \
		pulsecore/ioline.c pulsecore/ioline.h \
		pulsecore/ipacl.c pulsecore/ipacl.h \
		pulsecore/llist.h \
		pulsecore/lock-autospawn.c pulsecore/lock-autospawn.h \
		pulsecore/log.c pulsecore/log.h \
		pulsecore/ratelimit.c pulsecore/ratelimit.h \
		pulsecore/macro.h \
		pulsecore/mcalign.c pulsecore/mcalign.h \
		pulsecore/memblock.c pulsecore/memblock.h \
		pulsecore/memblockq.c pulsecore/memblockq.h \
		pulsecore/memchunk.c pulsecore/memchunk.h \
		pulsecore/native-common.c pulsecore/native-common.h \
		pulsecore/once.c pulsecore/once.h \
		pulsecore/packet.c pulsecore/packet.h \
		pulsecore/parseaddr.c pulsecore/parseaddr.h \
		pulsecore/pdispatch.c pulsecore/pdispatch.h \
		pulsecore/pid.c pulsecore/pid.h \
		pulsecore/pipe.c pulsecore/pipe.h \
		pulsecore/memtrap.c pulsecore/memtrap.h \
		pulsecore/aupdate.c pulsecore/aupdate.h \
		pulsecore/proplist-util.c pulsecore/proplist-util.h \
		pulsecore/pstream-util.c pulsecore/pstream-util.h \
		pulsecore/pstream.c pulsecore/pstream.h \
		pulsecore/queue.c pulsecore/queue.h \
		pulsecore/random.c pulsecore/random.h \
		pulsecore/refcnt.h \
		pulsecore/srbchannel.c pulsecore/srbchannel.h \
		pulsecore/sample-util.c pulsecore/sample-util.h \
		pulsecore/mem.h \
		pulsecore/shm.c pulsecore/shm.h \
		pulsecore/bitset.c pulsecore/bitset.h \
		pulsecore/socket-client.c pulsecore/socket-client.h \
		pulsecore/socket-server.c pulsecore/socket-server.h \
		pulsecore/socket-util.c pulsecore/socket-util.h \
		pulsecore/strbuf.c pulsecore/strbuf.h \
		pulsecore/strlist.c pulsecore/strlist.h \
		pulsecore/svolume_c.c pulsecore/svolume_arm.c \
		pulsecore/svolume_mmx.c pulsecore/svolume_sse.c \
		pulsecore/tagstruct.c pulsecore/tagstruct.h \
		pulsecore/time-smoother.c pulsecore/time-smoother.h \
		pulsecore/tokenizer.c pulsecore/tokenizer.h \
		pulsecore/usergroup.c pulsecore/usergroup.h \
		pulsecore/sndfile-util.c pulsecore/sndfile-util.h \
		pulsecore/socket.h

if OS_IS_WIN32
libpulsecommon_@PA_MAJORMINOR@_la_SOURCES += \
		pulsecore/poll-win32.c pulsecore/poll.h \
		pulsecore/winerrno.h
else
libpulsecommon_@PA_MAJORMINOR@_la_SOURCES += pulsecore/poll-posix.c pulsecore/poll.h
endif

libpulsecommon_@PA_MAJORMINOR@_la_CFLAGS = $(AM_CFLAGS) $(LIBSNDFILE_CFLAGS)
libpulsecommon_@PA_MAJORMINOR@_la_LDFLAGS = $(AM_LDFLAGS) $(AM_LIBLDFLAGS) -avoid-version
libpulsecommon_@PA_MAJORMINOR@_la_LIBADD = $(AM_LIBADD) $(LIBWRAP_LIBS) $(WINSOCK_LIBS) $(LTLIBICONV) $(LIBSNDFILE_LIBS)

if HAVE_MEMFD
libpulsecommon_@PA_MAJORMINOR@_la_SOURCES += \
		pulsecore/memfd-wrappers.h
endif

if HAVE_X11
libpulsecommon_@PA_MAJORMINOR@_la_SOURCES += \
		pulse/client-conf-x11.c pulse/client-conf-x11.h \
		pulsecore/x11prop.c pulsecore/x11prop.h
libpulsecommon_@PA_MAJORMINOR@_la_CFLAGS += $(X11_CFLAGS)
libpulsecommon_@PA_MAJORMINOR@_la_LDFLAGS += $(X11_LIBS)
endif

if HAVE_SYSTEMD_DAEMON
libpulsecommon_@PA_MAJORMINOR@_la_CFLAGS += $(SYSTEMD_FLAGS) $(SYSTEMDDAEMON_FLAGS)
libpulsecommon_@PA_MAJORMINOR@_la_LDFLAGS += $(SYSTEMD_LIBS) $(SYSTEMDDAEMON_LIBS)
endif
if HAVE_SYSTEMD_JOURNAL
libpulsecommon_@PA_MAJORMINOR@_la_CFLAGS += $(SYSTEMD_FLAGS) $(SYSTEMDJOURNAL_FLAGS)
libpulsecommon_@PA_MAJORMINOR@_la_LDFLAGS += $(SYSTEMD_LIBS) $(SYSTEMDJOURNAL_LIBS)
endif

# proplist-util.h uses these header files, but not the library itself!
libpulsecommon_@PA_MAJORMINOR@_la_CFLAGS += $(GLIB20_CFLAGS) $(GTK30_CFLAGS)

## Please note that libpulsecommon implicitly also depends on<
## libpulse! i.e. we have a cyclic dependancy here. Which is intended
## since libpulse only includes stable, official APIs, while
## libpulsecommon only includes unofficial APIs.

if OS_IS_WIN32
libpulsecommon_@PA_MAJORMINOR@_la_SOURCES += \
		pulsecore/mutex-win32.c pulsecore/mutex.h \
		pulsecore/thread-win32.c pulsecore/thread.h \
		pulsecore/semaphore-win32.c pulsecore/semaphore.h
else !OS_IS_WIN32
if OS_IS_DARWIN
libpulsecommon_@PA_MAJORMINOR@_la_SOURCES += \
		pulsecore/mutex-posix.c pulsecore/mutex.h \
		pulsecore/thread-posix.c pulsecore/thread.h \
		pulsecore/semaphore-osx.c pulsecore/semaphore.h
else !OS_IS_DARWIN
libpulsecommon_@PA_MAJORMINOR@_la_SOURCES += \
		pulsecore/mutex-posix.c pulsecore/mutex.h \
		pulsecore/thread-posix.c pulsecore/thread.h \
		pulsecore/semaphore-posix.c pulsecore/semaphore.h
endif !OS_IS_DARWIN
endif !OS_IS_WIN32

if HAVE_LIBASYNCNS
libpulsecommon_@PA_MAJORMINOR@_la_CFLAGS += $(LIBASYNCNS_CFLAGS)
libpulsecommon_@PA_MAJORMINOR@_la_LIBADD += $(LIBASYNCNS_LIBS)
endif

if OS_IS_WIN32
libpulsecommon_@PA_MAJORMINOR@_la_SOURCES += pulsecore/dllmain.c
endif

if HAVE_DBUS
libpulsecommon_@PA_MAJORMINOR@_la_SOURCES += \
		pulsecore/dbus-util.c pulsecore/dbus-util.h \
		pulsecore/rtkit.c pulsecore/rtkit.h
libpulsecommon_@PA_MAJORMINOR@_la_CFLAGS += $(DBUS_CFLAGS)
libpulsecommon_@PA_MAJORMINOR@_la_LIBADD += $(DBUS_LIBS)
endif

###################################
#         Client library          #
###################################

pulseinclude_HEADERS = \
		pulse/cdecl.h \
		pulse/channelmap.h \
		pulse/context.h \
		pulse/def.h \
		pulse/direction.h \
		pulse/error.h \
		pulse/ext-device-manager.h \
		pulse/ext-device-restore.h \
		pulse/ext-stream-restore.h \
		pulse/format.h \
		pulse/gccmacro.h \
		pulse/introspect.h \
		pulse/mainloop-api.h \
		pulse/mainloop-signal.h \
		pulse/mainloop.h \
		pulse/operation.h \
		pulse/proplist.h \
		pulse/pulseaudio.h \
		pulse/rtclock.h \
		pulse/sample.h \
		pulse/scache.h \
		pulse/simple.h \
		pulse/stream.h \
		pulse/subscribe.h \
		pulse/thread-mainloop.h \
		pulse/timeval.h \
		pulse/utf8.h \
		pulse/util.h \
		pulse/version.h \
		pulse/volume.h \
		pulse/xmalloc.h

lib_LTLIBRARIES = \
		libpulse.la \
		libpulse-simple.la

if HAVE_GLIB20
pulseinclude_HEADERS += \
		pulse/glib-mainloop.h

lib_LTLIBRARIES += \
		libpulse-mainloop-glib.la
endif

# Public interface
libpulse_la_SOURCES = \
		pulse/cdecl.h \
		pulse/channelmap.c pulse/channelmap.h \
		pulse/context.c pulse/context.h \
		pulse/def.h \
		pulse/direction.c pulse/direction.h \
		pulse/error.c pulse/error.h \
		pulse/ext-device-manager.c pulse/ext-device-manager.h \
		pulse/ext-device-restore.c pulse/ext-device-restore.h \
		pulse/ext-stream-restore.c pulse/ext-stream-restore.h \
		pulse/format.c pulse/format.h \
		pulse/gccmacro.h \
		pulse/internal.h \
		pulse/introspect.c pulse/introspect.h \
		pulse/mainloop-api.c pulse/mainloop-api.h \
		pulse/mainloop-signal.c pulse/mainloop-signal.h \
		pulse/mainloop.c pulse/mainloop.h \
		pulse/operation.c pulse/operation.h \
		pulse/proplist.c pulse/proplist.h \
		pulse/pulseaudio.h \
		pulse/rtclock.c pulse/rtclock.h \
		pulse/sample.c pulse/sample.h \
		pulse/scache.c pulse/scache.h \
		pulse/stream.c pulse/stream.h \
		pulse/subscribe.c pulse/subscribe.h \
		pulse/thread-mainloop.c pulse/thread-mainloop.h \
		pulse/timeval.c pulse/timeval.h \
		pulse/utf8.c pulse/utf8.h \
		pulse/util.c pulse/util.h \
		pulse/volume.c pulse/volume.h \
		pulse/xmalloc.c pulse/xmalloc.h

libpulse_la_CFLAGS = $(AM_CFLAGS)
libpulse_la_LIBADD = $(AM_LIBADD) $(WINSOCK_LIBS) $(LTLIBICONV) libpulsecommon-@PA_MAJORMINOR@.la
libpulse_la_LDFLAGS = $(AM_LDFLAGS) $(AM_LIBLDFLAGS) $(VERSIONING_LDFLAGS) -version-info $(LIBPULSE_VERSION_INFO)

if HAVE_DBUS
libpulse_la_CFLAGS += $(DBUS_CFLAGS)
libpulse_la_LIBADD += $(DBUS_LIBS)
endif

libpulse_simple_la_SOURCES = pulse/simple.c pulse/simple.h
libpulse_simple_la_CFLAGS = $(AM_CFLAGS)
libpulse_simple_la_LIBADD = $(AM_LIBADD) libpulse.la libpulsecommon-@PA_MAJORMINOR@.la
libpulse_simple_la_LDFLAGS = $(AM_LDFLAGS) $(AM_LIBLDFLAGS) $(VERSIONING_LDFLAGS) -version-info $(LIBPULSE_SIMPLE_VERSION_INFO)

libpulse_mainloop_glib_la_SOURCES = pulse/glib-mainloop.h pulse/glib-mainloop.c
libpulse_mainloop_glib_la_CFLAGS = $(AM_CFLAGS) $(GLIB20_CFLAGS)
libpulse_mainloop_glib_la_LIBADD = $(AM_LIBADD) libpulse.la libpulsecommon-@PA_MAJORMINOR@.la $(GLIB20_LIBS)
libpulse_mainloop_glib_la_LDFLAGS = $(AM_LDFLAGS) $(AM_LIBLDFLAGS) $(VERSIONING_LDFLAGS) -version-info $(LIBPULSE_MAINLOOP_GLIB_VERSION_INFO)

###################################
#         OSS emulation           #
###################################

if HAVE_OSS_WRAPPER
padsplibdir = $(pkglibdir)
padsplib_LTLIBRARIES = libpulsedsp.la
bin_SCRIPTS += padsp

edit = @SED@ \
       -e 's|@PULSEDSP_LOCATION[@]|$(PULSEDSP_LOCATION)|g'

padsp: utils/padsp.in
	$(edit) $< > $@

CLEANFILES += padsp

endif

libpulsedsp_la_SOURCES = utils/padsp.c
libpulsedsp_la_CFLAGS = $(AM_CFLAGS)
libpulsedsp_la_LIBADD = $(AM_LIBADD) libpulse.la libpulsecommon-@PA_MAJORMINOR@.la
libpulsedsp_la_LDFLAGS = $(AM_LDFLAGS) $(AM_LIBLDFLAGS) -avoid-version -disable-static

###################################
#      Daemon core library        #
###################################

pkglib_LTLIBRARIES = libpulsecore-@PA_MAJORMINOR@.la

# Pure core stuff
libpulsecore_@PA_MAJORMINOR@_la_SOURCES = \
		pulsecore/filter/lfe-filter.c pulsecore/filter/lfe-filter.h \
		pulsecore/filter/biquad.c pulsecore/filter/biquad.h \
		pulsecore/filter/crossover.c pulsecore/filter/crossover.h \
		pulsecore/asyncmsgq.c pulsecore/asyncmsgq.h \
		pulsecore/asyncq.c pulsecore/asyncq.h \
		pulsecore/auth-cookie.c pulsecore/auth-cookie.h \
		pulsecore/cli-command.c pulsecore/cli-command.h \
		pulsecore/cli-text.c pulsecore/cli-text.h \
		pulsecore/client.c pulsecore/client.h \
		pulsecore/typedefs.h \
		pulsecore/card.c pulsecore/card.h \
		pulsecore/core-scache.c pulsecore/core-scache.h \
		pulsecore/core-subscribe.c pulsecore/core-subscribe.h \
		pulsecore/core.c pulsecore/core.h \
		pulsecore/hook-list.c pulsecore/hook-list.h \
		pulsecore/ltdl-helper.c pulsecore/ltdl-helper.h \
		pulsecore/modargs.c pulsecore/modargs.h \
		pulsecore/modinfo.c pulsecore/modinfo.h \
		pulsecore/module.c pulsecore/module.h \
		pulsecore/msgobject.c pulsecore/msgobject.h \
		pulsecore/namereg.c pulsecore/namereg.h \
		pulsecore/object.c pulsecore/object.h \
		pulsecore/play-memblockq.c pulsecore/play-memblockq.h \
		pulsecore/play-memchunk.c pulsecore/play-memchunk.h \
		pulsecore/remap.c pulsecore/remap.h \
		pulsecore/remap_mmx.c pulsecore/remap_sse.c \
		pulsecore/resampler.c pulsecore/resampler.h \
		pulsecore/resampler/ffmpeg.c pulsecore/resampler/peaks.c \
		pulsecore/resampler/trivial.c \
		pulsecore/rtpoll.c pulsecore/rtpoll.h \
		pulsecore/stream-util.c pulsecore/stream-util.h \
		pulsecore/mix.c pulsecore/mix.h \
		pulsecore/cpu.c pulsecore/cpu.h \
		pulsecore/cpu-arm.c pulsecore/cpu-arm.h \
		pulsecore/cpu-x86.c pulsecore/cpu-x86.h \
		pulsecore/cpu-orc.c pulsecore/cpu-orc.h \
		pulsecore/sconv-s16be.c pulsecore/sconv-s16be.h \
		pulsecore/sconv-s16le.c pulsecore/sconv-s16le.h \
		pulsecore/sconv_sse.c \
		pulsecore/sconv.c pulsecore/sconv.h \
		pulsecore/shared.c pulsecore/shared.h \
		pulsecore/sink-input.c pulsecore/sink-input.h \
		pulsecore/sink.c pulsecore/sink.h \
		pulsecore/device-port.c pulsecore/device-port.h \
		pulsecore/sioman.c pulsecore/sioman.h \
		pulsecore/sound-file-stream.c pulsecore/sound-file-stream.h \
		pulsecore/sound-file.c pulsecore/sound-file.h \
		pulsecore/source-output.c pulsecore/source-output.h \
		pulsecore/source.c pulsecore/source.h \
		pulsecore/start-child.c pulsecore/start-child.h \
		pulsecore/thread-mq.c pulsecore/thread-mq.h \
		pulsecore/database.h

libpulsecore_@PA_MAJORMINOR@_la_CFLAGS = $(AM_CFLAGS) $(SERVER_CFLAGS) $(LIBSNDFILE_CFLAGS) $(WINSOCK_CFLAGS)
libpulsecore_@PA_MAJORMINOR@_la_LDFLAGS = $(AM_LDFLAGS) $(AM_LIBLDFLAGS) -avoid-version
libpulsecore_@PA_MAJORMINOR@_la_LIBADD = $(AM_LIBADD) $(LIBLTDL) $(LIBSNDFILE_LIBS) $(WINSOCK_LIBS) $(LTLIBICONV) libpulsecommon-@PA_MAJORMINOR@.la libpulse.la libpulsecore-foreign.la

if HAVE_NEON
noinst_LTLIBRARIES += libpulsecore_sconv_neon.la libpulsecore_mix_neon.la libpulsecore_remap_neon.la
libpulsecore_sconv_neon_la_SOURCES = pulsecore/sconv_neon.c
libpulsecore_sconv_neon_la_CFLAGS = $(AM_CFLAGS) $(NEON_CFLAGS)
libpulsecore_mix_neon_la_SOURCES = pulsecore/mix_neon.c
libpulsecore_mix_neon_la_CFLAGS = $(AM_CFLAGS) $(NEON_CFLAGS)
libpulsecore_remap_neon_la_SOURCES = pulsecore/remap_neon.c
libpulsecore_remap_neon_la_CFLAGS = $(AM_CFLAGS) $(NEON_CFLAGS)
libpulsecore_@PA_MAJORMINOR@_la_LIBADD += libpulsecore_sconv_neon.la libpulsecore_mix_neon.la libpulsecore_remap_neon.la
endif

ORC_SOURCE += pulsecore/svolume
if HAVE_ORC
libpulsecore_@PA_MAJORMINOR@_la_SOURCES += pulsecore/svolume_orc.c
nodist_libpulsecore_@PA_MAJORMINOR@_la_SOURCES = pulsecore/svolume-orc-gen.c pulsecore/svolume-orc-gen.h
libpulsecore_@PA_MAJORMINOR@_la_CFLAGS += $(ORC_CFLAGS)
libpulsecore_@PA_MAJORMINOR@_la_LIBADD += $(ORC_LIBS)
endif

if HAVE_X11
libpulsecore_@PA_MAJORMINOR@_la_SOURCES += pulsecore/x11wrap.c pulsecore/x11wrap.h
libpulsecore_@PA_MAJORMINOR@_la_CFLAGS += $(X11_CFLAGS)
libpulsecore_@PA_MAJORMINOR@_la_LDFLAGS += $(X11_LIBS)
endif

if HAVE_DBUS
libpulsecore_@PA_MAJORMINOR@_la_SOURCES += \
		pulsecore/dbus-shared.c pulsecore/dbus-shared.h \
		pulsecore/protocol-dbus.c pulsecore/protocol-dbus.h
libpulsecore_@PA_MAJORMINOR@_la_CFLAGS += $(DBUS_CFLAGS)
libpulsecore_@PA_MAJORMINOR@_la_LIBADD += $(DBUS_LIBS)
endif

if HAVE_GDBM
libpulsecore_@PA_MAJORMINOR@_la_SOURCES += pulsecore/database-gdbm.c
libpulsecore_@PA_MAJORMINOR@_la_CFLAGS += $(GDBM_CFLAGS)
libpulsecore_@PA_MAJORMINOR@_la_LIBADD += $(GDBM_LIBS)
endif

if HAVE_TDB
libpulsecore_@PA_MAJORMINOR@_la_SOURCES += pulsecore/database-tdb.c
libpulsecore_@PA_MAJORMINOR@_la_CFLAGS += $(TDB_CFLAGS)
libpulsecore_@PA_MAJORMINOR@_la_LIBADD += $(TDB_LIBS)
endif

if HAVE_SIMPLEDB
libpulsecore_@PA_MAJORMINOR@_la_SOURCES += pulsecore/database-simple.c
endif

if HAVE_SPEEX
libpulsecore_@PA_MAJORMINOR@_la_SOURCES += pulsecore/resampler/speex.c
libpulsecore_@PA_MAJORMINOR@_la_CFLAGS += $(LIBSPEEX_CFLAGS)
libpulsecore_@PA_MAJORMINOR@_la_LIBADD += $(LIBSPEEX_LIBS)
endif

if HAVE_SOXR
libpulsecore_@PA_MAJORMINOR@_la_SOURCES += pulsecore/resampler/soxr.c
libpulsecore_@PA_MAJORMINOR@_la_CFLAGS += $(LIBSOXR_CFLAGS)
libpulsecore_@PA_MAJORMINOR@_la_LIBADD += $(LIBSOXR_LIBS)
endif

if HAVE_LIBSAMPLERATE
libpulsecore_@PA_MAJORMINOR@_la_SOURCES += pulsecore/resampler/libsamplerate.c
libpulsecore_@PA_MAJORMINOR@_la_CFLAGS += $(LIBSAMPLERATE_CFLAGS)
libpulsecore_@PA_MAJORMINOR@_la_LIBADD += $(LIBSAMPLERATE_LIBS)
endif

# We split the foreign code off to not be annoyed by warnings we don't care about
noinst_LTLIBRARIES += libpulsecore-foreign.la

libpulsecore_foreign_la_SOURCES = \
		pulsecore/ffmpeg/resample2.c pulsecore/ffmpeg/avcodec.h pulsecore/ffmpeg/dsputil.h

libpulsecore_foreign_la_CFLAGS = $(AM_CFLAGS) $(FOREIGN_CFLAGS)

###################################
#   Plug-in support libraries     #
###################################

### Warning! Due to an obscure bug in libtool/automake it is required
### that the libraries in modlibexec_LTLIBRARIES are specified in-order,
### i.e. libraries near the end of the list depend on libraries near
### the head, and not the other way!

modlibexec_LTLIBRARIES = \
		libcli.la \
		libprotocol-cli.la \
		libprotocol-simple.la \
		libprotocol-http.la \
		libprotocol-native.la

if HAVE_WEBRTC
modlibexec_LTLIBRARIES += libwebrtc-util.la
endif

if HAVE_ESOUND
modlibexec_LTLIBRARIES += \
		libprotocol-esound.la
endif

# We need to emulate sendmsg/recvmsg to support this on Win32
if !OS_IS_WIN32
modlibexec_LTLIBRARIES += \
		librtp.la
endif

if HAVE_AVAHI
modlibexec_LTLIBRARIES += \
		libavahi-wrap.la
endif

libprotocol_simple_la_SOURCES = pulsecore/protocol-simple.c pulsecore/protocol-simple.h
libprotocol_simple_la_LDFLAGS = $(AM_LDFLAGS) $(AM_LIBLDFLAGS) -avoid-version
libprotocol_simple_la_LIBADD = $(AM_LIBADD) libpulsecore-@PA_MAJORMINOR@.la libpulsecommon-@PA_MAJORMINOR@.la libpulse.la

libcli_la_SOURCES = pulsecore/cli.c pulsecore/cli.h
libcli_la_LDFLAGS = $(AM_LDFLAGS) $(AM_LIBLDFLAGS) -avoid-version
libcli_la_LIBADD = $(AM_LIBADD) libpulsecore-@PA_MAJORMINOR@.la libpulsecommon-@PA_MAJORMINOR@.la libpulse.la

libprotocol_cli_la_SOURCES = pulsecore/protocol-cli.c pulsecore/protocol-cli.h
libprotocol_cli_la_LDFLAGS = $(AM_LDFLAGS) $(AM_LIBLDFLAGS) -avoid-version
libprotocol_cli_la_LIBADD = $(AM_LIBADD) libpulsecore-@PA_MAJORMINOR@.la libpulsecommon-@PA_MAJORMINOR@.la libpulse.la libcli.la

libprotocol_http_la_SOURCES = pulsecore/protocol-http.c pulsecore/protocol-http.h pulsecore/mime-type.c pulsecore/mime-type.h
libprotocol_http_la_LDFLAGS = $(AM_LDFLAGS) $(AM_LIBLDFLAGS) -avoid-version
libprotocol_http_la_LIBADD = $(AM_LIBADD) libpulsecore-@PA_MAJORMINOR@.la libpulsecommon-@PA_MAJORMINOR@.la libpulse.la

libprotocol_native_la_SOURCES = pulsecore/protocol-native.c pulsecore/protocol-native.h pulsecore/native-common.h
libprotocol_native_la_CFLAGS = $(AM_CFLAGS) $(SERVER_CFLAGS)
libprotocol_native_la_LDFLAGS = $(AM_LDFLAGS) $(AM_LIBLDFLAGS) -avoid-version
libprotocol_native_la_LIBADD = $(AM_LIBADD) libpulsecore-@PA_MAJORMINOR@.la libpulsecommon-@PA_MAJORMINOR@.la libpulse.la
if HAVE_DBUS
libprotocol_native_la_CFLAGS += $(DBUS_CFLAGS)
libprotocol_native_la_LIBADD += $(DBUS_LIBS)
endif

if HAVE_ESOUND
libprotocol_esound_la_SOURCES = pulsecore/protocol-esound.c pulsecore/protocol-esound.h pulsecore/esound.h
libprotocol_esound_la_LDFLAGS = $(AM_LDFLAGS) $(AM_LIBLDFLAGS) -avoid-version
libprotocol_esound_la_LIBADD = $(AM_LIBADD) libpulsecore-@PA_MAJORMINOR@.la libpulsecommon-@PA_MAJORMINOR@.la libpulse.la
endif

librtp_la_SOURCES = \
		modules/rtp/rtp.c modules/rtp/rtp.h \
		modules/rtp/sdp.c modules/rtp/sdp.h \
		modules/rtp/sap.c modules/rtp/sap.h \
		modules/rtp/rtsp_client.c modules/rtp/rtsp_client.h \
		modules/rtp/headerlist.c modules/rtp/headerlist.h
librtp_la_LDFLAGS = $(AM_LDFLAGS) $(AM_LIBLDFLAGS) -avoid-version
librtp_la_LIBADD = $(AM_LIBADD) libpulsecore-@PA_MAJORMINOR@.la libpulsecommon-@PA_MAJORMINOR@.la libpulse.la

libraop_la_SOURCES = \
        modules/raop/raop-util.c modules/raop/raop-util.h \
        modules/raop/raop-crypto.c modules/raop/raop-crypto.h \
        modules/raop/raop-packet-buffer.h modules/raop/raop-packet-buffer.c \
        modules/raop/raop-client.c modules/raop/raop-client.h \
        modules/raop/raop-sink.c modules/raop/raop-sink.h

libraop_la_CFLAGS = $(AM_CFLAGS) $(OPENSSL_CFLAGS) -I$(top_srcdir)/src/modules/rtp
libraop_la_LDFLAGS = $(AM_LDFLAGS) $(AM_LIBLDFLAGS) -avoid-version
libraop_la_LIBADD = $(AM_LIBADD) $(OPENSSL_LIBS) libpulsecore-@PA_MAJORMINOR@.la librtp.la libpulsecommon-@PA_MAJORMINOR@.la libpulse.la

# Avahi
libavahi_wrap_la_SOURCES = pulsecore/avahi-wrap.c pulsecore/avahi-wrap.h
libavahi_wrap_la_LDFLAGS = $(AM_LDFLAGS) $(AM_LIBLDFLAGS) -avoid-version
libavahi_wrap_la_CFLAGS = $(AM_CFLAGS) $(AVAHI_CFLAGS)
libavahi_wrap_la_LIBADD = $(AM_LIBADD) $(AVAHI_CFLAGS) libpulsecore-@PA_MAJORMINOR@.la libpulsecommon-@PA_MAJORMINOR@.la libpulse.la

###################################
#        Plug-in libraries        #
###################################

if HAVE_DBUS
# Serveral module (e.g. libalsa-util.la)
modlibexec_LTLIBRARIES += \
		module-console-kit.la
endif

modlibexec_LTLIBRARIES += \
		module-cli.la \
		module-cli-protocol-tcp.la \
		module-simple-protocol-tcp.la \
		module-null-sink.la \
		module-null-source.la \
		module-sine-source.la \
		module-detect.la \
		module-volume-restore.la \
		module-device-manager.la \
		module-device-restore.la \
		module-stream-restore.la \
		module-card-restore.la \
		module-default-device-restore.la \
		module-always-sink.la \
		module-always-source.la \
		module-rescue-streams.la \
		module-intended-roles.la \
		module-suspend-on-idle.la \
		module-echo-cancel.la \
		module-http-protocol-tcp.la \
		module-sine.la \
		module-native-protocol-tcp.la \
		module-native-protocol-fd.la \
		module-combine.la \
		module-combine-sink.la \
		module-remap-sink.la \
		module-remap-source.la \
		module-ladspa-sink.la \
		module-tunnel-sink-new.la \
		module-tunnel-source-new.la \
		module-tunnel-sink.la \
		module-tunnel-source.la \
		module-position-event-sounds.la \
		module-augment-properties.la \
		module-role-cork.la \
		module-loopback.la \
		module-virtual-sink.la \
		module-virtual-source.la \
		module-virtual-surround-sink.la \
		module-switch-on-connect.la \
		module-switch-on-port-available.la \
		module-filter-apply.la \
		module-filter-heuristics.la \
		module-role-ducking.la \
		module-allow-passthrough.la

if HAVE_ESOUND
modlibexec_LTLIBRARIES += \
		module-esound-protocol-tcp.la \
		module-esound-sink.la
endif

# See comment at librtp.la above
if !OS_IS_WIN32
modlibexec_LTLIBRARIES += \
		module-rtp-send.la \
		module-rtp-recv.la
endif

if HAVE_AF_UNIX
modlibexec_LTLIBRARIES += \
		module-cli-protocol-unix.la \
		module-simple-protocol-unix.la \
		module-http-protocol-unix.la \
		module-native-protocol-unix.la
if HAVE_ESOUND
modlibexec_LTLIBRARIES += \
		module-esound-protocol-unix.la
endif
endif

if HAVE_MKFIFO
modlibexec_LTLIBRARIES += \
		module-pipe-sink.la \
		module-pipe-source.la
endif

if !OS_IS_WIN32
if HAVE_ESOUND
modlibexec_LTLIBRARIES += \
		module-esound-compat-spawnfd.la \
		module-esound-compat-spawnpid.la
endif
endif

if HAVE_REGEX
modlibexec_LTLIBRARIES += \
		module-match.la
endif

if HAVE_X11
modlibexec_LTLIBRARIES += \
		module-x11-bell.la \
		module-x11-publish.la \
		module-x11-xsmp.la \
		module-x11-cork-request.la
endif

if HAVE_OSS_OUTPUT
modlibexec_LTLIBRARIES += \
		liboss-util.la \
		module-oss.la
endif

if HAVE_COREAUDIO
modlibexec_LTLIBRARIES += \
		module-coreaudio-detect.la \
		module-coreaudio-device.la
endif

pulselibexec_PROGRAMS =

if HAVE_ALSA
modlibexec_LTLIBRARIES += \
		libalsa-util.la \
		module-alsa-sink.la \
		module-alsa-source.la \
		module-alsa-card.la

dist_alsaprofilesets_DATA = \
		modules/alsa/mixer/profile-sets/default.conf \
		modules/alsa/mixer/profile-sets/force-speaker.conf \
		modules/alsa/mixer/profile-sets/force-speaker-and-int-mic.conf \
		modules/alsa/mixer/profile-sets/maudio-fasttrack-pro.conf \
		modules/alsa/mixer/profile-sets/native-instruments-audio4dj.conf \
		modules/alsa/mixer/profile-sets/native-instruments-audio8dj.conf \
		modules/alsa/mixer/profile-sets/native-instruments-traktor-audio2.conf \
		modules/alsa/mixer/profile-sets/native-instruments-traktor-audio6.conf \
		modules/alsa/mixer/profile-sets/native-instruments-traktor-audio10.conf \
		modules/alsa/mixer/profile-sets/native-instruments-traktorkontrol-s4.conf \
		modules/alsa/mixer/profile-sets/native-instruments-korecontroller.conf \
		modules/alsa/mixer/profile-sets/kinect-audio.conf \
		modules/alsa/mixer/profile-sets/sb-omni-surround-5.1.conf \
		modules/alsa/mixer/profile-sets/steelseries-arctis-5-usb-audio.conf \
		modules/alsa/mixer/profile-sets/steelseries-arctis-7-usb-audio.conf \
		modules/alsa/mixer/profile-sets/dell-dock-tb16-usb-audio.conf

if HAVE_UDEV
dist_udevrules_DATA = \
		modules/alsa/mixer/profile-sets/90-pulseaudio.rules
endif

dist_alsapaths_DATA = \
		modules/alsa/mixer/paths/analog-input-aux.conf \
		modules/alsa/mixer/paths/analog-input.conf \
		modules/alsa/mixer/paths/analog-input.conf.common \
		modules/alsa/mixer/paths/analog-input-fm.conf \
		modules/alsa/mixer/paths/analog-input-linein.conf \
		modules/alsa/mixer/paths/analog-input-mic.conf \
		modules/alsa/mixer/paths/analog-input-dock-mic.conf \
		modules/alsa/mixer/paths/analog-input-front-mic.conf \
		modules/alsa/mixer/paths/analog-input-headphone-mic.conf \
		modules/alsa/mixer/paths/analog-input-headset-mic.conf \
		modules/alsa/mixer/paths/analog-input-internal-mic.conf \
		modules/alsa/mixer/paths/analog-input-internal-mic-always.conf \
		modules/alsa/mixer/paths/analog-input-rear-mic.conf \
		modules/alsa/mixer/paths/analog-input-mic.conf.common \
		modules/alsa/mixer/paths/analog-input-mic-line.conf \
		modules/alsa/mixer/paths/analog-input-tvtuner.conf \
		modules/alsa/mixer/paths/analog-input-video.conf \
		modules/alsa/mixer/paths/analog-output.conf \
		modules/alsa/mixer/paths/analog-output-speaker.conf \
		modules/alsa/mixer/paths/analog-output-speaker-always.conf \
		modules/alsa/mixer/paths/analog-output.conf.common \
		modules/alsa/mixer/paths/analog-output-headphones.conf \
		modules/alsa/mixer/paths/analog-output-headphones-2.conf \
		modules/alsa/mixer/paths/analog-output-lineout.conf \
		modules/alsa/mixer/paths/analog-output-mono.conf \
		modules/alsa/mixer/paths/iec958-stereo-input.conf \
		modules/alsa/mixer/paths/iec958-stereo-output.conf \
		modules/alsa/mixer/paths/hdmi-output-0.conf \
		modules/alsa/mixer/paths/hdmi-output-1.conf \
		modules/alsa/mixer/paths/hdmi-output-2.conf \
		modules/alsa/mixer/paths/hdmi-output-3.conf \
		modules/alsa/mixer/paths/hdmi-output-4.conf \
		modules/alsa/mixer/paths/hdmi-output-5.conf \
		modules/alsa/mixer/paths/hdmi-output-6.conf \
		modules/alsa/mixer/paths/hdmi-output-7.conf \
		modules/alsa/mixer/paths/steelseries-arctis-5-output-chat.conf \
		modules/alsa/mixer/paths/steelseries-arctis-5-output-game.conf \
		modules/alsa/mixer/paths/steelseries-arctis-7-input.conf \
		modules/alsa/mixer/paths/steelseries-arctis-7-output-mono.conf \
		modules/alsa/mixer/paths/steelseries-arctis-7-output-stereo.conf

endif

if HAVE_SOLARIS
modlibexec_LTLIBRARIES += \
		module-solaris.la
endif

if HAVE_AVAHI
modlibexec_LTLIBRARIES += \
		module-zeroconf-publish.la \
		module-zeroconf-discover.la
endif

if HAVE_BONJOUR
modlibexec_LTLIBRARIES += \
		module-bonjour-publish.la
endif

if HAVE_LIRC
modlibexec_LTLIBRARIES += \
		module-lirc.la
endif

if HAVE_EVDEV
modlibexec_LTLIBRARIES += \
		module-mmkbd-evdev.la
endif

if HAVE_JACK
modlibexec_LTLIBRARIES += \
		module-jack-sink.la \
		module-jack-source.la

if HAVE_DBUS
modlibexec_LTLIBRARIES += \
		module-jackdbus-detect.la
endif

endif

if HAVE_GCONF
modlibexec_LTLIBRARIES += \
		module-gconf.la

pulselibexec_PROGRAMS += \
		gconf-helper
endif

if HAVE_GSETTINGS
modlibexec_LTLIBRARIES += \
		module-gsettings.la

pulselibexec_PROGRAMS += \
		gsettings-helper

gsettingsdataconvert_DATA = \
		modules/gsettings/pulseaudio.convert
endif

if HAVE_WAVEOUT
modlibexec_LTLIBRARIES += \
		module-waveout.la
endif

if HAVE_HAL_COMPAT
modlibexec_LTLIBRARIES += \
		module-hal-detect.la
endif

if HAVE_UDEV
modlibexec_LTLIBRARIES += \
		module-udev-detect.la
endif

if HAVE_SYSTEMD_LOGIN
modlibexec_LTLIBRARIES += \
		module-systemd-login.la
endif

if HAVE_DBUS
modlibexec_LTLIBRARIES += \
		module-rygel-media-server.la \
		module-dbus-protocol.la
endif

if HAVE_BLUEZ
modlibexec_LTLIBRARIES += \
		module-bluetooth-discover.la \
		module-bluetooth-policy.la
endif

if HAVE_BLUEZ_5
modlibexec_LTLIBRARIES += \
		libbluez5-util.la \
		module-bluez5-discover.la \
		module-bluez5-device.la
endif

# RAOP depends on RTP, and we don't support RTP on Windows, see comment at
# librtp.la above.
if !OS_IS_WIN32
if HAVE_OPENSSL
modlibexec_LTLIBRARIES += \
		libraop.la \
		module-raop-sink.la
if HAVE_AVAHI
modlibexec_LTLIBRARIES += \
		module-raop-discover.la
endif
endif
endif

if HAVE_DBUS
if HAVE_FFTW
modlibexec_LTLIBRARIES += \
		module-equalizer-sink.la
bin_SCRIPTS += utils/qpaeq
endif
endif

# Simple protocol

module_simple_protocol_tcp_la_SOURCES = modules/module-protocol-stub.c
module_simple_protocol_tcp_la_CFLAGS = -DUSE_TCP_SOCKETS -DUSE_PROTOCOL_SIMPLE $(AM_CFLAGS) -DPA_MODULE_NAME=module_simple_protocol_tcp
module_simple_protocol_tcp_la_LDFLAGS = $(MODULE_LDFLAGS)
module_simple_protocol_tcp_la_LIBADD = $(MODULE_LIBADD) libprotocol-simple.la

module_simple_protocol_unix_la_SOURCES = modules/module-protocol-stub.c
module_simple_protocol_unix_la_CFLAGS = -DUSE_UNIX_SOCKETS -DUSE_PROTOCOL_SIMPLE $(AM_CFLAGS) -DPA_MODULE_NAME=module_simple_protocol_unix
module_simple_protocol_unix_la_LDFLAGS = $(MODULE_LDFLAGS)
module_simple_protocol_unix_la_LIBADD = $(MODULE_LIBADD) libprotocol-simple.la

# CLI protocol

module_cli_la_SOURCES = modules/module-cli.c
module_cli_la_LDFLAGS = $(MODULE_LDFLAGS)
module_cli_la_LIBADD = $(MODULE_LIBADD) libcli.la
module_cli_la_CFLAGS = $(AM_CFLAGS) -DPA_MODULE_NAME=module_cli

module_cli_protocol_tcp_la_SOURCES = modules/module-protocol-stub.c
module_cli_protocol_tcp_la_CFLAGS = -DUSE_TCP_SOCKETS -DUSE_PROTOCOL_CLI $(AM_CFLAGS) -DPA_MODULE_NAME=module_cli_protocol_tcp
module_cli_protocol_tcp_la_LDFLAGS = $(MODULE_LDFLAGS)
module_cli_protocol_tcp_la_LIBADD = $(MODULE_LIBADD) libprotocol-cli.la

module_cli_protocol_unix_la_SOURCES = modules/module-protocol-stub.c
module_cli_protocol_unix_la_CFLAGS = -DUSE_UNIX_SOCKETS -DUSE_PROTOCOL_CLI $(AM_CFLAGS) -DPA_MODULE_NAME=module_cli_protocol_unix
module_cli_protocol_unix_la_LDFLAGS = $(MODULE_LDFLAGS)
module_cli_protocol_unix_la_LIBADD = $(MODULE_LIBADD) libprotocol-cli.la

# HTTP protocol

module_http_protocol_tcp_la_SOURCES = modules/module-protocol-stub.c
module_http_protocol_tcp_la_CFLAGS = -DUSE_TCP_SOCKETS -DUSE_PROTOCOL_HTTP $(AM_CFLAGS) -DPA_MODULE_NAME=module_http_protocol_tcp
module_http_protocol_tcp_la_LDFLAGS = $(MODULE_LDFLAGS)
module_http_protocol_tcp_la_LIBADD = $(MODULE_LIBADD) libprotocol-http.la

module_http_protocol_unix_la_SOURCES = modules/module-protocol-stub.c
module_http_protocol_unix_la_CFLAGS = -DUSE_UNIX_SOCKETS -DUSE_PROTOCOL_HTTP $(AM_CFLAGS) -DPA_MODULE_NAME=module_http_protocol_unix
module_http_protocol_unix_la_LDFLAGS = $(MODULE_LDFLAGS)
module_http_protocol_unix_la_LIBADD = $(MODULE_LIBADD) libprotocol-http.la

# D-Bus protocol

module_dbus_protocol_la_SOURCES = \
		modules/dbus/iface-card.c modules/dbus/iface-card.h \
		modules/dbus/iface-card-profile.c modules/dbus/iface-card-profile.h \
		modules/dbus/iface-client.c modules/dbus/iface-client.h \
		modules/dbus/iface-core.c modules/dbus/iface-core.h \
		modules/dbus/iface-device.c modules/dbus/iface-device.h \
		modules/dbus/iface-device-port.c modules/dbus/iface-device-port.h \
		modules/dbus/iface-memstats.c modules/dbus/iface-memstats.h \
		modules/dbus/iface-module.c modules/dbus/iface-module.h \
		modules/dbus/iface-sample.c modules/dbus/iface-sample.h \
		modules/dbus/iface-stream.c modules/dbus/iface-stream.h \
		modules/dbus/module-dbus-protocol.c
module_dbus_protocol_la_CFLAGS = $(AM_CFLAGS) $(DBUS_CFLAGS) -DPA_MODULE_NAME=module_dbus_protocol
module_dbus_protocol_la_LDFLAGS = $(MODULE_LDFLAGS)
module_dbus_protocol_la_LIBADD = $(MODULE_LIBADD) $(DBUS_LIBS)

# Native protocol

module_native_protocol_tcp_la_SOURCES = modules/module-protocol-stub.c
module_native_protocol_tcp_la_CFLAGS = -DUSE_TCP_SOCKETS -DUSE_PROTOCOL_NATIVE $(AM_CFLAGS) -DPA_MODULE_NAME=module_native_protocol_tcp
module_native_protocol_tcp_la_LDFLAGS = $(MODULE_LDFLAGS)
module_native_protocol_tcp_la_LIBADD = $(MODULE_LIBADD) libprotocol-native.la

module_native_protocol_unix_la_SOURCES = modules/module-protocol-stub.c
module_native_protocol_unix_la_CFLAGS = -DUSE_UNIX_SOCKETS -DUSE_PROTOCOL_NATIVE $(AM_CFLAGS) -DPA_MODULE_NAME=module_native_protocol_unix
module_native_protocol_unix_la_LDFLAGS = $(MODULE_LDFLAGS)
module_native_protocol_unix_la_LIBADD = $(MODULE_LIBADD) libprotocol-native.la

module_native_protocol_fd_la_SOURCES = modules/module-native-protocol-fd.c
module_native_protocol_fd_la_CFLAGS = $(AM_CFLAGS) -DPA_MODULE_NAME=module_native_protocol_fd
module_native_protocol_fd_la_LDFLAGS = $(MODULE_LDFLAGS)
module_native_protocol_fd_la_LIBADD = $(MODULE_LIBADD) libprotocol-native.la

# EsounD protocol

if HAVE_ESOUND
module_esound_protocol_tcp_la_SOURCES = modules/module-protocol-stub.c
module_esound_protocol_tcp_la_CFLAGS = -DUSE_TCP_SOCKETS -DUSE_PROTOCOL_ESOUND $(AM_CFLAGS) -DPA_MODULE_NAME=module_esound_protocol_tcp
module_esound_protocol_tcp_la_LDFLAGS = $(MODULE_LDFLAGS)
module_esound_protocol_tcp_la_LIBADD = $(MODULE_LIBADD) libprotocol-esound.la

module_esound_protocol_unix_la_SOURCES = modules/module-protocol-stub.c
module_esound_protocol_unix_la_CFLAGS = -DUSE_UNIX_SOCKETS -DUSE_PROTOCOL_ESOUND $(AM_CFLAGS) -DPA_MODULE_NAME=module_esound_protocol_unix
module_esound_protocol_unix_la_LDFLAGS = $(MODULE_LDFLAGS)
module_esound_protocol_unix_la_LIBADD = $(MODULE_LIBADD) libprotocol-esound.la

module_esound_compat_spawnfd_la_SOURCES = modules/module-esound-compat-spawnfd.c
module_esound_compat_spawnfd_la_CFLAGS = $(AM_CFLAGS) -DPA_MODULE_NAME=module_esound_compat_spawnfd
module_esound_compat_spawnfd_la_LDFLAGS = $(MODULE_LDFLAGS)
module_esound_compat_spawnfd_la_LIBADD = $(MODULE_LIBADD)

module_esound_compat_spawnpid_la_SOURCES = modules/module-esound-compat-spawnpid.c
module_esound_compat_spawnpid_la_CFLAGS = $(AM_CFLAGS) -DPA_MODULE_NAME=module_esound_compat_spawnpid
module_esound_compat_spawnpid_la_LDFLAGS = $(MODULE_LDFLAGS)
module_esound_compat_spawnpid_la_LIBADD = $(MODULE_LIBADD)

module_esound_sink_la_SOURCES = modules/module-esound-sink.c
module_esound_sink_la_CFLAGS = $(AM_CFLAGS) -DPA_MODULE_NAME=module_esound_sink
module_esound_sink_la_LDFLAGS = $(MODULE_LDFLAGS) $(WINSOCK_LIBS)
module_esound_sink_la_LIBADD = $(MODULE_LIBADD)
endif

# Pipes

module_pipe_sink_la_SOURCES = modules/module-pipe-sink.c
module_pipe_sink_la_LDFLAGS = $(MODULE_LDFLAGS)
module_pipe_sink_la_LIBADD = $(MODULE_LIBADD)
module_pipe_sink_la_CFLAGS = $(AM_CFLAGS) -DPA_MODULE_NAME=module_pipe_sink

module_pipe_source_la_SOURCES = modules/module-pipe-source.c
module_pipe_source_la_LDFLAGS = $(MODULE_LDFLAGS)
module_pipe_source_la_LIBADD = $(MODULE_LIBADD)
module_pipe_source_la_CFLAGS = $(AM_CFLAGS) -DPA_MODULE_NAME=module_pipe_source

# Fake sources/sinks

module_sine_la_SOURCES = modules/module-sine.c
module_sine_la_LDFLAGS = $(MODULE_LDFLAGS)
module_sine_la_LIBADD = $(MODULE_LIBADD)
module_sine_la_CFLAGS = $(AM_CFLAGS) -DPA_MODULE_NAME=module_sine

module_null_sink_la_SOURCES = modules/module-null-sink.c
module_null_sink_la_LDFLAGS = $(MODULE_LDFLAGS)
module_null_sink_la_LIBADD = $(MODULE_LIBADD)
module_null_sink_la_CFLAGS = $(AM_CFLAGS) -DPA_MODULE_NAME=module_null_sink

module_null_source_la_SOURCES = modules/module-null-source.c
module_null_source_la_LDFLAGS = $(MODULE_LDFLAGS)
module_null_source_la_LIBADD = $(MODULE_LIBADD)
module_null_source_la_CFLAGS = $(AM_CFLAGS) -DPA_MODULE_NAME=module_null_source

module_sine_source_la_SOURCES = modules/module-sine-source.c
module_sine_source_la_LDFLAGS = $(MODULE_LDFLAGS)
module_sine_source_la_LIBADD = $(MODULE_LIBADD)
module_sine_source_la_CFLAGS = $(AM_CFLAGS) -DPA_MODULE_NAME=module_sine_source

# Couplings

module_combine_la_SOURCES = modules/module-combine.c
module_combine_la_LDFLAGS = $(MODULE_LDFLAGS)
module_combine_la_LIBADD = $(MODULE_LIBADD)
module_combine_la_CFLAGS = $(AM_CFLAGS) -DPA_MODULE_NAME=module_combine

module_combine_sink_la_SOURCES = modules/module-combine-sink.c
module_combine_sink_la_LDFLAGS = $(MODULE_LDFLAGS)
module_combine_sink_la_LIBADD = $(MODULE_LIBADD)
module_combine_sink_la_CFLAGS = $(AM_CFLAGS) -DPA_MODULE_NAME=module_combine_sink

module_switch_on_connect_la_SOURCES = modules/module-switch-on-connect.c
module_switch_on_connect_la_LDFLAGS = $(MODULE_LDFLAGS)
module_switch_on_connect_la_LIBADD = $(MODULE_LIBADD)
module_switch_on_connect_la_CFLAGS = $(AM_CFLAGS) -DPA_MODULE_NAME=module_switch_on_connect

module_switch_on_port_available_la_SOURCES = modules/module-switch-on-port-available.c
module_switch_on_port_available_la_LDFLAGS = $(MODULE_LDFLAGS)
module_switch_on_port_available_la_LIBADD = $(MODULE_LIBADD)
module_switch_on_port_available_la_CFLAGS = $(AM_CFLAGS) -DPA_MODULE_NAME=module_switch_on_port_available

module_filter_apply_la_SOURCES = modules/module-filter-apply.c
module_filter_apply_la_LDFLAGS = $(MODULE_LDFLAGS)
module_filter_apply_la_LIBADD = $(MODULE_LIBADD)
module_filter_apply_la_CFLAGS = $(AM_CFLAGS) -DPA_MODULE_NAME=module_filter_apply

module_filter_heuristics_la_SOURCES = modules/module-filter-heuristics.c
module_filter_heuristics_la_LDFLAGS = $(MODULE_LDFLAGS)
module_filter_heuristics_la_LIBADD = $(MODULE_LIBADD)
module_filter_heuristics_la_CFLAGS = $(AM_CFLAGS) -DPA_MODULE_NAME=module_filter_heuristics

module_remap_sink_la_SOURCES = modules/module-remap-sink.c
module_remap_sink_la_LDFLAGS = $(MODULE_LDFLAGS)
module_remap_sink_la_LIBADD = $(MODULE_LIBADD)
module_remap_sink_la_CFLAGS = $(AM_CFLAGS) -DPA_MODULE_NAME=module_remap_sink

module_remap_source_la_SOURCES = modules/module-remap-source.c
module_remap_source_la_LDFLAGS = $(MODULE_LDFLAGS)
module_remap_source_la_LIBADD = $(MODULE_LIBADD)
module_remap_source_la_CFLAGS = $(AM_CFLAGS) -DPA_MODULE_NAME=module_remap_source

module_ladspa_sink_la_SOURCES = modules/module-ladspa-sink.c modules/ladspa.h
module_ladspa_sink_la_CFLAGS = -DLADSPA_PATH="$(libdir)/ladspa:/usr/local/lib/ladspa:/usr/lib/ladspa:/usr/local/lib64/ladspa:/usr/lib64/ladspa" $(AM_CFLAGS) $(SERVER_CFLAGS) -DPA_MODULE_NAME=module_ladspa_sink
module_ladspa_sink_la_LDFLAGS = $(MODULE_LDFLAGS)
module_ladspa_sink_la_LIBADD = $(MODULE_LIBADD) $(LIBLTDL)

if HAVE_DBUS
module_ladspa_sink_la_CFLAGS += $(DBUS_CFLAGS)
module_ladspa_sink_la_LIBADD += $(DBUS_LIBS)
endif

module_equalizer_sink_la_SOURCES = modules/module-equalizer-sink.c
module_equalizer_sink_la_CFLAGS = $(AM_CFLAGS) $(SERVER_CFLAGS) $(DBUS_CFLAGS) $(FFTW_CFLAGS) -DPA_MODULE_NAME=module_equalizer_sink
module_equalizer_sink_la_LDFLAGS = $(MODULE_LDFLAGS)
module_equalizer_sink_la_LIBADD = $(MODULE_LIBADD) $(DBUS_LIBS) $(FFTW_LIBS)

module_match_la_SOURCES = modules/module-match.c
module_match_la_LDFLAGS = $(MODULE_LDFLAGS)
module_match_la_LIBADD = $(MODULE_LIBADD)
module_match_la_CFLAGS = $(AM_CFLAGS) -DPA_MODULE_NAME=module_match

module_tunnel_sink_new_la_SOURCES = modules/module-tunnel-sink-new.c
module_tunnel_sink_new_la_LDFLAGS = $(MODULE_LDFLAGS)
module_tunnel_sink_new_la_LIBADD = $(MODULE_LIBADD)
module_tunnel_sink_new_la_CFLAGS = $(AM_CFLAGS) -DPA_MODULE_NAME=module_tunnel_sink_new

module_tunnel_source_new_la_SOURCES = modules/module-tunnel-source-new.c
module_tunnel_source_new_la_LDFLAGS = $(MODULE_LDFLAGS)
module_tunnel_source_new_la_LIBADD = $(MODULE_LIBADD)
module_tunnel_source_new_la_CFLAGS = $(AM_CFLAGS) -DPA_MODULE_NAME=module_tunnel_source_new

module_tunnel_sink_la_SOURCES = modules/module-tunnel.c
module_tunnel_sink_la_CFLAGS = -DTUNNEL_SINK=1 $(AM_CFLAGS) $(X11_CFLAGS) -DPA_MODULE_NAME=module_tunnel_sink
module_tunnel_sink_la_LDFLAGS = $(MODULE_LDFLAGS)
module_tunnel_sink_la_LIBADD = $(MODULE_LIBADD) $(X11_LIBS)

module_tunnel_source_la_SOURCES = modules/module-tunnel.c
module_tunnel_source_la_LDFLAGS = $(MODULE_LDFLAGS) $(X11_CFLAGS)
module_tunnel_source_la_LIBADD = $(MODULE_LIBADD) $(X11_LIBS)
module_tunnel_source_la_CFLAGS = $(AM_CFLAGS) -DPA_MODULE_NAME=module_tunnel_source

module_loopback_la_SOURCES = modules/module-loopback.c
module_loopback_la_LDFLAGS = $(MODULE_LDFLAGS)
module_loopback_la_LIBADD = $(MODULE_LIBADD)
module_loopback_la_CFLAGS = $(AM_CFLAGS) -DPA_MODULE_NAME=module_loopback

module_virtual_sink_la_SOURCES = modules/module-virtual-sink.c
module_virtual_sink_la_CFLAGS = $(AM_CFLAGS) $(SERVER_CFLAGS) -DPA_MODULE_NAME=module_virtual_sink
module_virtual_sink_la_LDFLAGS = $(MODULE_LDFLAGS)
module_virtual_sink_la_LIBADD = $(MODULE_LIBADD)

module_virtual_source_la_SOURCES = modules/module-virtual-source.c
module_virtual_source_la_CFLAGS = $(AM_CFLAGS) $(SERVER_CFLAGS) -DPA_MODULE_NAME=module_virtual_source
module_virtual_source_la_LDFLAGS = $(MODULE_LDFLAGS)
module_virtual_source_la_LIBADD = $(MODULE_LIBADD)

module_virtual_surround_sink_la_SOURCES = modules/module-virtual-surround-sink.c
module_virtual_surround_sink_la_CFLAGS = $(AM_CFLAGS) $(SERVER_CFLAGS) -DPA_MODULE_NAME=module_virtual_surround_sink
module_virtual_surround_sink_la_LDFLAGS = $(MODULE_LDFLAGS)
module_virtual_surround_sink_la_LIBADD = $(MODULE_LIBADD)

# X11

module_x11_bell_la_SOURCES = modules/x11/module-x11-bell.c
module_x11_bell_la_CFLAGS = $(AM_CFLAGS) $(X11_CFLAGS) -DPA_MODULE_NAME=module_x11_bell
module_x11_bell_la_LDFLAGS = $(MODULE_LDFLAGS)
module_x11_bell_la_LIBADD = $(MODULE_LIBADD) $(X11_LIBS)

module_x11_publish_la_SOURCES = modules/x11/module-x11-publish.c
module_x11_publish_la_CFLAGS = $(AM_CFLAGS) $(X11_CFLAGS) -DPA_MODULE_NAME=module_x11_publish
module_x11_publish_la_LDFLAGS = $(MODULE_LDFLAGS)
module_x11_publish_la_LIBADD = $(MODULE_LIBADD) libprotocol-native.la $(X11_LIBS)

module_x11_xsmp_la_SOURCES = modules/x11/module-x11-xsmp.c
module_x11_xsmp_la_CFLAGS = $(AM_CFLAGS) $(X11_CFLAGS) -DPA_MODULE_NAME=module_x11_xsmp
module_x11_xsmp_la_LDFLAGS = $(MODULE_LDFLAGS)
module_x11_xsmp_la_LIBADD = $(MODULE_LIBADD) $(X11_LIBS)

module_x11_cork_request_la_SOURCES = modules/x11/module-x11-cork-request.c
module_x11_cork_request_la_CFLAGS = $(AM_CFLAGS) $(X11_CFLAGS) -DPA_MODULE_NAME=module_x11_cork_request
module_x11_cork_request_la_LDFLAGS = $(MODULE_LDFLAGS)
module_x11_cork_request_la_LIBADD = $(MODULE_LIBADD) $(X11_LIBS)

# OSS

liboss_util_la_SOURCES = modules/oss/oss-util.c modules/oss/oss-util.h
liboss_util_la_LDFLAGS = -avoid-version
liboss_util_la_LIBADD = $(MODULE_LIBADD)

module_oss_la_SOURCES = modules/oss/module-oss.c
module_oss_la_LDFLAGS = $(MODULE_LDFLAGS)
module_oss_la_LIBADD = $(MODULE_LIBADD) liboss-util.la
module_oss_la_CFLAGS = $(AM_CFLAGS) -DPA_MODULE_NAME=module_oss

# COREAUDIO

module_coreaudio_detect_la_SOURCES = modules/macosx/module-coreaudio-detect.c
module_coreaudio_detect_la_LDFLAGS = $(MODULE_LDFLAGS) \
		-Wl,-framework -Wl,Cocoa -framework CoreAudio \
		-Wl,-framework -Wl,AudioUnit -framework AudioUnit
module_coreaudio_detect_la_LIBADD = $(MODULE_LIBADD)
module_coreaudio_detect_la_CFLAGS = $(AM_CFLAGS) -DPA_MODULE_NAME=module_coreaudio_detect

module_coreaudio_device_la_SOURCES = modules/macosx/module-coreaudio-device.c
module_coreaudio_device_la_LDFLAGS = $(MODULE_LDFLAGS) \
		-Wl,-framework -Wl,Cocoa -framework CoreAudio \
		-Wl,-framework -Wl,AudioUnit -framework AudioUnit
module_coreaudio_device_la_LIBADD = $(MODULE_LIBADD)
module_coreaudio_device_la_CFLAGS = $(AM_CFLAGS) -DPA_MODULE_NAME=module_coreaudio_device

# ALSA

libalsa_util_la_SOURCES = \
		modules/alsa/alsa-util.c modules/alsa/alsa-util.h \
		modules/alsa/alsa-ucm.c modules/alsa/alsa-ucm.h \
		modules/alsa/alsa-mixer.c modules/alsa/alsa-mixer.h \
		modules/alsa/alsa-sink.c modules/alsa/alsa-sink.h \
		modules/alsa/alsa-source.c modules/alsa/alsa-source.h \
		modules/reserve-wrap.c modules/reserve-wrap.h
libalsa_util_la_LDFLAGS = -avoid-version
libalsa_util_la_LIBADD = $(MODULE_LIBADD) $(ASOUNDLIB_LIBS)
libalsa_util_la_CFLAGS = $(AM_CFLAGS) $(SERVER_CFLAGS) $(ASOUNDLIB_CFLAGS)

if HAVE_UDEV
libalsa_util_la_SOURCES += modules/udev-util.h modules/udev-util.c
libalsa_util_la_LIBADD += $(UDEV_LIBS)
libalsa_util_la_CFLAGS += $(UDEV_CFLAGS)
endif

if HAVE_DBUS
libalsa_util_la_SOURCES += modules/reserve.h modules/reserve.c modules/reserve-monitor.h modules/reserve-monitor.c
libalsa_util_la_LIBADD += $(DBUS_LIBS)
libalsa_util_la_CFLAGS += $(DBUS_CFLAGS)
endif

module_alsa_sink_la_SOURCES = modules/alsa/module-alsa-sink.c
module_alsa_sink_la_LDFLAGS = $(MODULE_LDFLAGS)
module_alsa_sink_la_LIBADD = $(MODULE_LIBADD) $(ASOUNDLIB_LIBS) libalsa-util.la
module_alsa_sink_la_CFLAGS = $(AM_CFLAGS) $(ASOUNDLIB_CFLAGS) -DPA_MODULE_NAME=module_alsa_sink

module_alsa_source_la_SOURCES = modules/alsa/module-alsa-source.c
module_alsa_source_la_LDFLAGS = $(MODULE_LDFLAGS)
module_alsa_source_la_LIBADD = $(MODULE_LIBADD) $(ASOUNDLIB_LIBS) libalsa-util.la
module_alsa_source_la_CFLAGS = $(AM_CFLAGS) $(ASOUNDLIB_CFLAGS) -DPA_MODULE_NAME=module_alsa_source

module_alsa_card_la_SOURCES = modules/alsa/module-alsa-card.c
module_alsa_card_la_LDFLAGS = $(MODULE_LDFLAGS)
module_alsa_card_la_LIBADD = $(MODULE_LIBADD) $(ASOUNDLIB_LIBS) libalsa-util.la
module_alsa_card_la_CFLAGS = $(AM_CFLAGS) $(ASOUNDLIB_CFLAGS) -DPA_MODULE_NAME=module_alsa_card

# Solaris

module_solaris_la_SOURCES = modules/module-solaris.c
module_solaris_la_LDFLAGS = $(MODULE_LDFLAGS)
module_solaris_la_LIBADD = $(MODULE_LIBADD)
module_solaris_la_CFLAGS = $(AM_CFLAGS) -DPA_MODULE_NAME=module_solaris

# Avahi

module_zeroconf_publish_la_SOURCES = modules/module-zeroconf-publish.c
module_zeroconf_publish_la_LDFLAGS = $(MODULE_LDFLAGS)
module_zeroconf_publish_la_LIBADD = $(MODULE_LIBADD) $(AVAHI_LIBS) $(DBUS_LIBS) libavahi-wrap.la libprotocol-native.la
module_zeroconf_publish_la_CFLAGS = $(AM_CFLAGS) $(AVAHI_CFLAGS) $(DBUS_CFLAGS) -DPA_MODULE_NAME=module_zeroconf_publish

module_zeroconf_discover_la_SOURCES = modules/module-zeroconf-discover.c
module_zeroconf_discover_la_LDFLAGS = $(MODULE_LDFLAGS)
module_zeroconf_discover_la_LIBADD = $(MODULE_LIBADD) $(AVAHI_LIBS) libavahi-wrap.la
module_zeroconf_discover_la_CFLAGS = $(AM_CFLAGS) $(AVAHI_CFLAGS) -DPA_MODULE_NAME=module_zeroconf_discover

# Bonjour

module_bonjour_publish_la_SOURCES = modules/macosx/module-bonjour-publish.c
module_bonjour_publish_la_LDFLAGS = $(MODULE_LDFLAGS) \
			-Wl,-framework -Wl,CoreFoundation -framework CoreFoundation
module_bonjour_publish_la_LIBADD = $(MODULE_LIBADD) libprotocol-native.la
module_bonjour_publish_la_CFLAGS = $(AM_CFLAGS) -DPA_MODULE_NAME=module_bonjour_publish

# LIRC

module_lirc_la_SOURCES = modules/module-lirc.c
module_lirc_la_LDFLAGS = $(MODULE_LDFLAGS)
module_lirc_la_LIBADD = $(MODULE_LIBADD) $(LIRC_LIBS)
module_lirc_la_CFLAGS = $(AM_CFLAGS) $(LIRC_CFLAGS) -DPA_MODULE_NAME=module_lirc


# Linux evdev

module_mmkbd_evdev_la_SOURCES = modules/module-mmkbd-evdev.c
module_mmkbd_evdev_la_LDFLAGS = $(MODULE_LDFLAGS)
module_mmkbd_evdev_la_LIBADD = $(MODULE_LIBADD)
module_mmkbd_evdev_la_CFLAGS = $(AM_CFLAGS) -DPA_MODULE_NAME=module_mmkbd_evdev

# Windows waveout
module_waveout_la_SOURCES = modules/module-waveout.c
module_waveout_la_LDFLAGS = $(MODULE_LDFLAGS)
module_waveout_la_LIBADD = $(MODULE_LIBADD) -lwinmm
module_waveout_la_CFLAGS = $(AM_CFLAGS) -DPA_MODULE_NAME=module_waveout

# Hardware autodetection module
module_detect_la_SOURCES = modules/module-detect.c
module_detect_la_LDFLAGS = $(MODULE_LDFLAGS)
module_detect_la_LIBADD = $(MODULE_LIBADD)
module_detect_la_CFLAGS = $(AM_CFLAGS) -DPA_MODULE_NAME=module_detect

# Volume restore module
module_volume_restore_la_SOURCES = modules/module-volume-restore.c
module_volume_restore_la_LDFLAGS = $(MODULE_LDFLAGS)
module_volume_restore_la_LIBADD = $(MODULE_LIBADD)
module_volume_restore_la_CFLAGS = $(AM_CFLAGS) -DPA_MODULE_NAME=module_volume_restore

# Position event sounds in space
module_position_event_sounds_la_SOURCES = modules/module-position-event-sounds.c
module_position_event_sounds_la_LDFLAGS = $(MODULE_LDFLAGS)
module_position_event_sounds_la_LIBADD = $(MODULE_LIBADD)
module_position_event_sounds_la_CFLAGS = $(AM_CFLAGS) -DPA_MODULE_NAME=module_position_event_sounds

# Ducking effect based on stream roles
module_role_ducking_la_SOURCES = modules/module-role-ducking.c \
                                 modules/stream-interaction.c modules/stream-interaction.h
module_role_ducking_la_LDFLAGS = $(MODULE_LDFLAGS)
module_role_ducking_la_LIBADD = $(MODULE_LIBADD)
module_role_ducking_la_CFLAGS = $(AM_CFLAGS) -DPA_MODULE_NAME=module_role_ducking

# Augment properties from XDG .desktop files
module_augment_properties_la_SOURCES = modules/module-augment-properties.c
module_augment_properties_la_LDFLAGS = $(MODULE_LDFLAGS)
module_augment_properties_la_LIBADD = $(MODULE_LIBADD)
#module_augment_properties_la_CFLAGS = $(AM_CFLAGS) -DDESKTOPFILEDIR=\"$(datadir)/applications\"
module_augment_properties_la_CFLAGS = $(AM_CFLAGS) -DDESKTOPFILEDIR=\"/usr/share/applications\" -DPA_MODULE_NAME=module_augment_properties

# Cork certain streams while others are active (e.g. cork music when phone streams appear)
module_role_cork_la_SOURCES = modules/module-role-cork.c \
                              modules/stream-interaction.c modules/stream-interaction.h
module_role_cork_la_LDFLAGS = $(MODULE_LDFLAGS)
module_role_cork_la_LIBADD = $(MODULE_LIBADD)
module_role_cork_la_CFLAGS = $(AM_CFLAGS) -DPA_MODULE_NAME=module_role_cork

# Device description restore module
module_device_manager_la_SOURCES = modules/module-device-manager.c
module_device_manager_la_LDFLAGS = $(MODULE_LDFLAGS)
module_device_manager_la_LIBADD = $(MODULE_LIBADD) libprotocol-native.la
module_device_manager_la_CFLAGS = $(AM_CFLAGS) -DPA_MODULE_NAME=module_device_manager

# Device volume/muted restore module
module_device_restore_la_SOURCES = modules/module-device-restore.c
module_device_restore_la_LDFLAGS = $(MODULE_LDFLAGS)
module_device_restore_la_LIBADD = $(MODULE_LIBADD) libprotocol-native.la
module_device_restore_la_CFLAGS = $(AM_CFLAGS) -DPA_MODULE_NAME=module_device_restore

if HAVE_DBUS
module_device_restore_la_LIBADD += $(DBUS_LIBS)
module_device_restore_la_CFLAGS += $(DBUS_CFLAGS)
endif

# Stream volume/muted/device restore module
module_stream_restore_la_SOURCES = modules/module-stream-restore.c
module_stream_restore_la_LDFLAGS = $(MODULE_LDFLAGS)
module_stream_restore_la_LIBADD = $(MODULE_LIBADD) libprotocol-native.la
module_stream_restore_la_CFLAGS = $(AM_CFLAGS) -DPA_MODULE_NAME=module_stream_restore

if HAVE_DBUS
module_stream_restore_la_LIBADD += $(DBUS_LIBS)
module_stream_restore_la_CFLAGS += $(DBUS_CFLAGS)
endif

# Card profile restore module
module_card_restore_la_SOURCES = modules/module-card-restore.c
module_card_restore_la_LDFLAGS = $(MODULE_LDFLAGS)
module_card_restore_la_LIBADD = $(MODULE_LIBADD)
module_card_restore_la_CFLAGS = $(AM_CFLAGS) -DPA_MODULE_NAME=module_card_restore

# Default sink/source restore module
module_default_device_restore_la_SOURCES = modules/module-default-device-restore.c
module_default_device_restore_la_LDFLAGS = $(MODULE_LDFLAGS)
module_default_device_restore_la_LIBADD = $(MODULE_LIBADD)
module_default_device_restore_la_CFLAGS = $(AM_CFLAGS) -DPA_MODULE_NAME=module_default_device_restore

# Always Sink module
module_always_sink_la_SOURCES = modules/module-always-sink.c
module_always_sink_la_LDFLAGS = $(MODULE_LDFLAGS)
module_always_sink_la_LIBADD = $(MODULE_LIBADD)
module_always_sink_la_CFLAGS = $(AM_CFLAGS) -DPA_MODULE_NAME=module_always_sink

# Always Source module
module_always_source_la_SOURCES = modules/module-always-source.c
module_always_source_la_LDFLAGS = $(MODULE_LDFLAGS)
module_always_source_la_LIBADD = $(MODULE_LIBADD)
module_always_source_la_CFLAGS = $(AM_CFLAGS) -DPA_MODULE_NAME=module_always_source

# Rescue streams module
module_rescue_streams_la_SOURCES = modules/module-rescue-streams.c
module_rescue_streams_la_LDFLAGS = $(MODULE_LDFLAGS)
module_rescue_streams_la_LIBADD = $(MODULE_LIBADD)
module_rescue_streams_la_CFLAGS = $(AM_CFLAGS) -DPA_MODULE_NAME=module_rescue_streams

# Automatically move streams to devices that are intended for their roles
module_intended_roles_la_SOURCES = modules/module-intended-roles.c
module_intended_roles_la_LDFLAGS = $(MODULE_LDFLAGS)
module_intended_roles_la_LIBADD = $(MODULE_LIBADD)
module_intended_roles_la_CFLAGS = $(AM_CFLAGS) -DPA_MODULE_NAME=module_intended_roles

# Suspend-on-idle module
module_suspend_on_idle_la_SOURCES = modules/module-suspend-on-idle.c
module_suspend_on_idle_la_LDFLAGS = $(MODULE_LDFLAGS)
module_suspend_on_idle_la_LIBADD = $(MODULE_LIBADD)
module_suspend_on_idle_la_CFLAGS = $(AM_CFLAGS) -DPA_MODULE_NAME=module_suspend_on_idle

# echo-cancel module
module_echo_cancel_la_SOURCES = \
		modules/echo-cancel/module-echo-cancel.c \
		modules/echo-cancel/null.c \
		modules/echo-cancel/echo-cancel.h
module_echo_cancel_la_LDFLAGS = $(MODULE_LDFLAGS)
module_echo_cancel_la_LIBADD = $(MODULE_LIBADD)
module_echo_cancel_la_CFLAGS = $(AM_CFLAGS) $(SERVER_CFLAGS) -DPA_MODULE_NAME=module_echo_cancel
if HAVE_ADRIAN_EC
module_echo_cancel_la_SOURCES += \
		modules/echo-cancel/adrian-aec.c modules/echo-cancel/adrian-aec.h \
		modules/echo-cancel/adrian.c modules/echo-cancel/adrian.h
module_echo_cancel_la_CFLAGS += -DHAVE_ADRIAN_EC=1
ORC_SOURCE += modules/echo-cancel/adrian-aec
if HAVE_ORC
nodist_module_echo_cancel_la_SOURCES = \
		modules/echo-cancel/adrian-aec-orc-gen.c \
		modules/echo-cancel/adrian-aec-orc-gen.h
module_echo_cancel_la_LIBADD += $(ORC_LIBS)
module_echo_cancel_la_CFLAGS += $(ORC_CFLAGS) -I$(top_builddir)/src/modules/echo-cancel
endif
endif
if HAVE_SPEEX
module_echo_cancel_la_SOURCES += modules/echo-cancel/speex.c
module_echo_cancel_la_CFLAGS += $(LIBSPEEX_CFLAGS)
module_echo_cancel_la_LIBADD += $(LIBSPEEX_LIBS)
endif
if HAVE_WEBRTC
# The webrtc code is split off into a helper library to avoid having automake
# link module-echo-cancel with C++ (which it does if there are any C++ deps,
# even conditional ones).

libwebrtc_util_la_SOURCES = modules/echo-cancel/webrtc.cc
libwebrtc_util_la_CXXFLAGS = $(AM_CXXFLAGS) $(SERVER_CFLAGS) $(WEBRTC_CFLAGS) -DHAVE_WEBRTC=1
libwebrtc_util_la_LIBADD = libpulsecore-@PA_MAJORMINOR@.la $(WEBRTC_LIBS)
libwebrtc_util_la_LDFLAGS = -avoid-version

module_echo_cancel_la_CFLAGS += -DHAVE_WEBRTC=1
module_echo_cancel_la_LIBADD += libwebrtc-util.la
endif

# RTP modules
module_rtp_send_la_SOURCES = modules/rtp/module-rtp-send.c
module_rtp_send_la_LDFLAGS = $(MODULE_LDFLAGS)
module_rtp_send_la_LIBADD = $(MODULE_LIBADD) librtp.la
module_rtp_send_la_CFLAGS = $(AM_CFLAGS) -DPA_MODULE_NAME=module_rtp_send

module_rtp_recv_la_SOURCES = modules/rtp/module-rtp-recv.c
module_rtp_recv_la_LDFLAGS = $(MODULE_LDFLAGS)
module_rtp_recv_la_LIBADD = $(MODULE_LIBADD) librtp.la
module_rtp_recv_la_CFLAGS = $(AM_CFLAGS) -DPA_MODULE_NAME=module_rtp_recv

# JACK

module_jackdbus_detect_la_SOURCES = modules/jack/module-jackdbus-detect.c
module_jackdbus_detect_la_LDFLAGS = $(MODULE_LDFLAGS)
module_jackdbus_detect_la_LIBADD = $(MODULE_LIBADD) $(DBUS_LIBS) $(JACK_LIBS)
module_jackdbus_detect_la_CFLAGS = $(AM_CFLAGS) $(DBUS_CFLAGS) $(JACK_CFLAGS) -DPA_MODULE_NAME=module_jackdbus_detect

module_jack_sink_la_SOURCES = modules/jack/module-jack-sink.c
module_jack_sink_la_LDFLAGS = $(MODULE_LDFLAGS)
module_jack_sink_la_LIBADD = $(MODULE_LIBADD) $(JACK_LIBS)
module_jack_sink_la_CFLAGS = $(AM_CFLAGS) $(JACK_CFLAGS) -DPA_MODULE_NAME=module_jack_sink

module_jack_source_la_SOURCES = modules/jack/module-jack-source.c
module_jack_source_la_LDFLAGS = $(MODULE_LDFLAGS)
module_jack_source_la_LIBADD = $(MODULE_LIBADD) $(JACK_LIBS)
module_jack_source_la_CFLAGS = $(AM_CFLAGS) $(JACK_CFLAGS) -DPA_MODULE_NAME=module_jack_source

module_hal_detect_la_SOURCES = modules/module-hal-detect-compat.c
module_hal_detect_la_LIBADD = $(MODULE_LIBADD)
module_hal_detect_la_CFLAGS = $(AM_CFLAGS) -DPA_MODULE_NAME=module_hal_detect
module_hal_detect_la_LDFLAGS = $(MODULE_LDFLAGS)

module_udev_detect_la_SOURCES = modules/module-udev-detect.c
module_udev_detect_la_LDFLAGS = $(MODULE_LDFLAGS)
module_udev_detect_la_LIBADD = $(MODULE_LIBADD) $(UDEV_LIBS)
module_udev_detect_la_CFLAGS = $(AM_CFLAGS) $(UDEV_CFLAGS) -DPA_MODULE_NAME=module_udev_detect

module_console_kit_la_SOURCES = modules/module-console-kit.c
module_console_kit_la_LDFLAGS = $(MODULE_LDFLAGS)
module_console_kit_la_LIBADD = $(MODULE_LIBADD) $(DBUS_LIBS)
module_console_kit_la_CFLAGS = $(AM_CFLAGS) $(DBUS_CFLAGS) -DPA_MODULE_NAME=module_console_kit

module_systemd_login_la_SOURCES = modules/module-systemd-login.c
module_systemd_login_la_LDFLAGS = $(MODULE_LDFLAGS)
module_systemd_login_la_LIBADD = $(MODULE_LIBADD) $(SYSTEMD_LIBS) $(SYSTEMDLOGIN_LIBS)
module_systemd_login_la_CFLAGS = $(AM_CFLAGS) $(SYSTEMD_CFLAGS) $(SYSTEMDLOGIN_CFLAGS) -DPA_MODULE_NAME=module_systemd_login

# GConf support
module_gconf_la_SOURCES = \
		 modules/stdin-util.c modules/stdin-util.h \
		 modules/gconf/module-gconf.c

module_gconf_la_LDFLAGS = $(MODULE_LDFLAGS)
module_gconf_la_LIBADD = $(MODULE_LIBADD)
module_gconf_la_CFLAGS = $(AM_CFLAGS) -DPA_GCONF_HELPER=\"$(pulselibexecdir)/gconf-helper\" -DPA_MODULE_NAME=module_gconf

gconf_helper_SOURCES = modules/gconf/gconf-helper.c
gconf_helper_LDADD = $(AM_LDADD) libpulsecore-@PA_MAJORMINOR@.la libpulsecommon-@PA_MAJORMINOR@.la libpulse.la $(GCONF_LIBS)
gconf_helper_CFLAGS = $(AM_CFLAGS) $(GCONF_CFLAGS)
gconf_helper_LDFLAGS = $(AM_LDFLAGS) $(BINLDFLAGS)

# GSettings support
module_gsettings_la_SOURCES = \
		modules/stdin-util.c modules/stdin-util.h \
		modules/gsettings/module-gsettings.c
module_gsettings_la_LDFLAGS = $(MODULE_LDFLAGS)
module_gsettings_la_LIBADD = $(MODULE_LIBADD)
module_gsettings_la_CFLAGS = $(AM_CFLAGS) -DPA_GSETTINGS_HELPER=\"$(pulselibexecdir)/gsettings-helper\" -DPA_MODULE_NAME=module_gsettings

gsettings_helper_SOURCES = modules/gsettings/gsettings-helper.c
gsettings_helper_LDADD = $(AM_LDADD) libpulsecore-@PA_MAJORMINOR@.la libpulsecommon-@PA_MAJORMINOR@.la libpulse.la $(GSETTINGS_LIBS)
gsettings_helper_CFLAGS = $(AM_CFLAGS) $(GSETTINGS_CFLAGS)
gsettings_helper_LDFLAGS = $(AM_LDFLAGS) $(BINLDFLAGS)

if HAVE_GSETTINGS
gsettings_SCHEMAS = modules/gsettings/org.freedesktop.pulseaudio.gschema.xml
@GSETTINGS_RULES@
endif

# Bluetooth policy
module_bluetooth_policy_la_SOURCES = modules/bluetooth/module-bluetooth-policy.c
module_bluetooth_policy_la_LDFLAGS = $(MODULE_LDFLAGS)
module_bluetooth_policy_la_LIBADD = $(MODULE_LIBADD)
module_bluetooth_policy_la_CFLAGS = $(AM_CFLAGS) $(DBUS_CFLAGS) -DPA_MODULE_NAME=module_bluetooth_policy

# Bluetooth discover
module_bluetooth_discover_la_SOURCES = modules/bluetooth/module-bluetooth-discover.c
module_bluetooth_discover_la_LDFLAGS = $(MODULE_LDFLAGS)
module_bluetooth_discover_la_LIBADD = $(MODULE_LIBADD)
module_bluetooth_discover_la_CFLAGS = $(AM_CFLAGS) -DPA_MODULE_NAME=module_bluetooth_discover

# Bluetooth BlueZ 5 sink / source
libbluez5_util_la_SOURCES = \
		modules/bluetooth/bluez5-util.c \
		modules/bluetooth/bluez5-util.h \
		modules/bluetooth/a2dp-codecs.h
if HAVE_BLUEZ_5_OFONO_HEADSET
libbluez5_util_la_SOURCES += \
		modules/bluetooth/backend-ofono.c
endif
if HAVE_BLUEZ_5_NATIVE_HEADSET
libbluez5_util_la_SOURCES += \
		modules/bluetooth/backend-native.c
endif

libbluez5_util_la_LDFLAGS = -avoid-version
libbluez5_util_la_LIBADD = $(MODULE_LIBADD) $(DBUS_LIBS)
libbluez5_util_la_CFLAGS = $(AM_CFLAGS) $(DBUS_CFLAGS)

module_bluez5_discover_la_SOURCES = modules/bluetooth/module-bluez5-discover.c
module_bluez5_discover_la_LDFLAGS = $(MODULE_LDFLAGS)
module_bluez5_discover_la_LIBADD = $(MODULE_LIBADD) $(DBUS_LIBS) libbluez5-util.la
module_bluez5_discover_la_CFLAGS = $(AM_CFLAGS) $(DBUS_CFLAGS) -DPA_MODULE_NAME=module_bluez5_discover

module_bluez5_device_la_SOURCES = modules/bluetooth/module-bluez5-device.c
module_bluez5_device_la_LDFLAGS = $(MODULE_LDFLAGS)
module_bluez5_device_la_LIBADD = $(MODULE_LIBADD) $(SBC_LIBS) libbluez5-util.la
module_bluez5_device_la_CFLAGS = $(AM_CFLAGS) $(SBC_CFLAGS) -DPA_MODULE_NAME=module_bluez5_device

# Apple Airtunes/RAOP
module_raop_sink_la_SOURCES = modules/raop/module-raop-sink.c
module_raop_sink_la_LDFLAGS = $(MODULE_LDFLAGS)
module_raop_sink_la_LIBADD = $(MODULE_LIBADD) librtp.la libraop.la
module_raop_sink_la_CFLAGS = $(AM_CFLAGS) -I$(top_srcdir)/src/modules/rtp -DPA_MODULE_NAME=module_raop_sink

module_raop_discover_la_SOURCES = modules/raop/module-raop-discover.c
module_raop_discover_la_LDFLAGS = $(MODULE_LDFLAGS)
module_raop_discover_la_LIBADD = $(MODULE_LIBADD) $(AVAHI_LIBS) libavahi-wrap.la
module_raop_discover_la_CFLAGS = $(AM_CFLAGS) $(AVAHI_CFLAGS) -DPA_MODULE_NAME=module_raop_discover

# Rygel
module_rygel_media_server_la_SOURCES = modules/module-rygel-media-server.c
module_rygel_media_server_la_LDFLAGS = $(MODULE_LDFLAGS)
module_rygel_media_server_la_LIBADD = $(MODULE_LIBADD) $(DBUS_LIBS) libprotocol-http.la
module_rygel_media_server_la_CFLAGS = $(AM_CFLAGS) $(DBUS_CFLAGS) -DPA_MODULE_NAME=module_rygel_media_server

# Allow passthrough module
module_allow_passthrough_la_SOURCES = modules/module-allow-passthrough.c
module_allow_passthrough_la_LDFLAGS = $(MODULE_LDFLAGS)
module_allow_passthrough_la_LIBADD = $(MODULE_LIBADD)
module_allow_passthrough_la_CFLAGS = $(AM_CFLAGS) -DPA_MODULE_NAME=module_allow_passthrough

###################################
#        Some minor stuff         #
###################################

CLEANFILES += daemon/pulseaudio.desktop
DISTCLEANFILES = esdcompat client.conf default.pa system.pa daemon.conf start-pulseaudio-x11 pulseaudio.service

if OS_IS_WIN32
SYMLINK_PROGRAM=cd $(DESTDIR)$(bindir) && cp
else
SYMLINK_PROGRAM=ln -sf
endif
install-exec-hook:
	$(SYMLINK_PROGRAM) pacat$(EXEEXT) $(DESTDIR)$(bindir)/parec$(EXEEXT)
	$(SYMLINK_PROGRAM) pacat$(EXEEXT) $(DESTDIR)$(bindir)/pamon$(EXEEXT)
	$(SYMLINK_PROGRAM) pacat$(EXEEXT) $(DESTDIR)$(bindir)/paplay$(EXEEXT)
	$(SYMLINK_PROGRAM) pacat$(EXEEXT) $(DESTDIR)$(bindir)/parecord$(EXEEXT)
	rm -f $(DESTDIR)$(libdir)/libpulsedsp.la
	rm -f $(DESTDIR)$(modlibexecdir)/*.la

uninstall-hook:
	rm -f $(DESTDIR)$(bindir)/parec$(EXEEXT)
	rm -f $(DESTDIR)$(bindir)/pamon$(EXEEXT)
	rm -f $(DESTDIR)$(bindir)/paplay$(EXEEXT)
	rm -f $(DESTDIR)$(bindir)/parecord$(EXEEXT)
	rm -f $(DESTDIR)$(libdir)/libpulsedsp.*
	rm -f $(DESTDIR)$(modlibexecdir)/*.so

massif: pulseaudio
	libtool --mode=execute valgrind --tool=massif --depth=6  --alloc-fn=pa_xmalloc --alloc-fn=pa_xmalloc0 --alloc-fn=pa_xrealloc --alloc-fn=dbus_realloc --alloc-fn=pa_xnew0_internal --alloc-fn=pa_xnew_internal ./pulseaudio

update-ffmpeg:
	wget -O pulsecore/ffmpeg/resample2.c http://svn.mplayerhq.hu/ffmpeg/trunk/libavcodec/resample2.c?view=co

update-reserve:
	for i in reserve.c reserve.h reserve-monitor.c reserve-monitor.h ; do \
		wget -O $(top_srcdir)/src/modules/$$i http://git.0pointer.de/\?p=reserve.git\;a=blob_plain\;f=$$i\;hb=master ; \
	done

update-rtkit:
	for i in rtkit.c rtkit.h ; do \
		wget -O $(top_srcdir)/src/pulsecore/$$i http://git.0pointer.de/\?p=rtkit.git\;a=blob_plain\;f=$$i\;hb=master ; \
	done

# Automatically generate linker version script. We use the same one for all public .sos
update-map-file:
	( echo "PULSE_0 {" ; \
	  echo "global:" ; \
	  ctags -I PA_GCC_MALLOC,PA_GCC_ALLOC_SIZE2,PA_GCC_ALLOC_SIZE,PA_GCC_PURE,PA_GCC_CONST,PA_GCC_DEPRECATED,PA_GCC_PRINTF_ATTR -f - --c-kinds=p $(pulseinclude_HEADERS) | awk '/^pa_/ { print $$1 ";" }' | sort ; \
	  echo "local:" ;  \
	  echo "*;" ; \
	  echo "};" ) > $(srcdir)/map-file

update-all: update-ffmpeg update-map-file

# Force installation order of libraries. libtool relinks on install time, in
# which case libpulsecommon has to be installed before others, but the padsp
# preload library has to be done after the normal libraries (e.g. libpulse)
# ...
# Unfortunately automake behaviour means that rules without commands also
# override build-in rules, so it's not trivial to add dependencies.
# See http://debbugs.gnu.org/cgi/bugreport.cgi?bug=7328 for the workaround
# ...
# Isn't libtool/autotools fun!

installlibLTLIBRARIES = install-libLTLIBRARIES
$(installlibLTLIBRARIES): install-commonlibLTLIBRARIES

installpkglibLTLIBRARIES = install-pkglibLTLIBRARIES
$(installpkglibLTLIBRARIES): install-libLTLIBRARIES

installmodlibexecLTLIBRARIES = install-modlibexecLTLIBRARIES
$(installmodlibexecLTLIBRARIES): install-pkglibLTLIBRARIES install-libLTLIBRARIES

installpadsplibLTLIBRARIES = install-padsplibLTLIBRARIES
$(installpadsplibLTLIBRARIES): install-libLTLIBRARIES

if HAVE_GCOV
coverage:
	@echo ""
	@echo "Don't forget to run 'make check' before generating coverage stats."
	@echo ""
	lcov --capture --directory . --output-file $(builddir)/gcov-all.info
	-rm -r $(builddir)/coverage
	genhtml --output-directory $(builddir)/coverage gcov-all.info
	@echo ""
	@echo "Coverage data now available at: $(abs_builddir)/coverage/index.html"
else
coverage:
	@echo ""
	@echo "To generate coverage stats, rerun configure with '--enable-gcov',"
	@echo "and don't forget to disable it again for regular builds."
	@echo ""
endif

.PHONY: massif update-all update-ffmpeg update-map-file coverage

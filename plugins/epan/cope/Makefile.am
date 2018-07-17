# Makefile.am
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

include $(top_srcdir)/Makefile.am.inc
include $(top_srcdir)/plugins/epan/Makefile.am.inc

# the name of the plugin
PLUGIN_NAME = cope

PLUGIN_VERSION = 1.1.0

BUILT_SOURCES = \
	plugin.c

# Non-generated sources to be scanned for registration routines
NONGENERATED_REGISTER_C_FILES = \
	packet-cope.c

# Non-generated sources
NONGENERATED_C_FILES = \
	$(NONGENERATED_REGISTER_C_FILES)

# Headers.
CLEAN_HEADER_FILES = \
	packet-cope.h

HEADER_FILES = \
	$(CLEAN_HEADER_FILES)

epan_plugin_LTLIBRARIES = cope.la

cope_la_SOURCES = \
	$(SRC_FILES)	\
	$(HEADER_FILES)

nodist_cope_la_SOURCES = \
	plugin.c

cope_la_CPPFLAGS = $(AM_CPPFLAGS) $(PLUGIN_CPPFLAGS)

cope_la_CFLAGS = $(AM_CFLAGS) $(PLUGIN_CFLAGS)

cope_la_LDFLAGS = $(PLUGIN_LDFLAGS)

DISTCLEANFILES = \
	plugin.c

EXTRA_DIST = \
	CMakeLists.txt

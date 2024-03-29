# Makefile.am
# Automake file for Wiretap
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

AM_CPPFLAGS = $(INCLUDEDIRS) $(WS_CPPFLAGS) -DWS_BUILD_DLL $(GLIB_CFLAGS) \
		$(PCAP_CFLAGS)

lib_LTLIBRARIES = libwiretap.la

# C source files that are part of the Wiretap source; this includes only
# .c files, not YACC or Lex or... files (as Makefile.nmake maps this list
# into a list of object files by replacing ".c" with ".obj") or files
# generated from YACC or Lex files (as Automake doesn't want them in
# _SOURCES variables).
NONGENERATED_C_FILES = \
	5views.c		\
	aethra.c		\
	ascendtext.c		\
	atm.c			\
	ber.c			\
	btsnoop.c		\
	camins.c		\
	capsa.c			\
	catapult_dct2000.c	\
	commview.c		\
	cosine.c		\
	csids.c			\
	daintree-sna.c		\
	dbs-etherwatch.c	\
	dct3trace.c		\
	erf.c			\
	eyesdn.c		\
	file_access.c		\
	file_wrappers.c		\
	hcidump.c		\
	i4btrace.c		\
	ipfix.c			\
	iptrace.c		\
	iseries.c		\
	mime_file.c		\
	json.c			\
	k12.c			\
	lanalyzer.c		\
	logcat_text.c		\
	logcat.c		\
	libpcap.c		\
	merge.c			\
	mpeg.c			\
	mplog.c			\
	mp2t.c			\
	netmon.c		\
	netscaler.c		\
	netscreen.c		\
	nettl.c			\
	nettrace_3gpp_32_423.c	\
	network_instruments.c	\
	netxray.c		\
	ngsniffer.c		\
	packetlogger.c		\
	pcap-common.c		\
	pcapng.c		\
	peekclassic.c           \
	peektagged.c		\
	pppdump.c		\
	radcom.c		\
	snoop.c			\
	stanag4607.c		\
	tnef.c			\
	toshiba.c		\
	visual.c		\
	vms.c			\
	vwr.c			\
	wtap.c			\
	wtap_opttypes.c

# Header files that are not generated from other files
NONGENERATED_HEADER_FILES = \
	5views.h		\
	aethra.h		\
	ascendtext.h		\
	ascend-int.h		\
	atm.h			\
	ber.h			\
	btsnoop.h		\
	camins.h		\
	capsa.h			\
	catapult_dct2000.h	\
	commview.h		\
	cosine.h		\
	csids.h			\
	daintree-sna.h		\
	dbs-etherwatch.h	\
	dct3trace.h		\
	erf.h			\
	eyesdn.h		\
	hcidump.h		\
	i4btrace.h		\
	i4b_trace.h		\
	ipfix.h			\
	iptrace.h		\
	iseries.h		\
	json.h			\
	mime_file.h		\
	k12.h			\
	lanalyzer.h		\
	libpcap.h		\
	logcat.h		\
	logcat_text.h		\
	mpeg.h			\
	mplog.h			\
	mp2t.h			\
	netmon.h		\
	netscreen.h		\
	netscaler.h		\
	nettl.h			\
	nettrace_3gpp_32_423.h	\
	network_instruments.h	\
	netxray.h		\
	ngsniffer.h		\
	packetlogger.h		\
	pcap-common.h		\
	pcapng.h		\
	peekclassic.h           \
	peektagged.h		\
	pppdump.h		\
	radcom.h		\
	snoop.h			\
	stanag4607.h		\
	tnef.h			\
	toshiba.h		\
	visual.h		\
	vms.h			\
	vwr.h			\
	wtap-int.h

PUBLIC_HEADER_FILES = \
	file_wrappers.h		\
	merge.h			\
	pcap-encap.h		\
	pcapng_module.h		\
	wtap.h			\
	wtap_opttypes.h

# Files that generate compileable files
GENERATOR_FILES = \
       ascend.y			\
       ascend_scanner.l		\
       k12text.l

# The C source files they generate.
GENERATED_C_FILES = \
	ascend.c		\
	ascend_scanner.c	\
	k12text.c

# The header files that they generate.
GENERATED_HEADER_FILES = \
	ascend.h		\
	ascend_scanner_lex.h	\
	k12text_lex.h

# All the generated files.
GENERATED_FILES = $(GENERATED_C_FILES) $(GENERATED_HEADER_FILES)

libwiretap_la_SOURCES = \
	$(NONGENERATED_C_FILES)		\
	$(NONGENERATED_HEADER_FILES)	\
	$(GENERATED_C_FILES)		\
	version_info.c

# http://www.gnu.org/software/libtool/manual/html_node/Updating-version-info.html
libwiretap_la_LDFLAGS = -version-info 8:1:0 @LDFLAGS_SHAREDLIB@

libwiretap_la_LIBADD = ${top_builddir}/wsutil/libwsutil.la $(GLIB_LIBS)

libwiretap_la_DEPENDENCIES = ${top_builddir}/wsutil/libwsutil.la

subpkgincludedir = $(pkgincludedir)/wiretap

subpkginclude_HEADERS = $(PUBLIC_HEADER_FILES)

DISTCLEANFILES = \
	version_info.c

MAINTAINERCLEANFILES = \
	$(GENERATED_FILES)

BUILT_SOURCES = $(GENERATED_HEADER_FILES) version_info.c

EXTRA_DIST = \
	.editorconfig		\
	README.airmagnet	\
	README.developer	\
	CMakeLists.txt		\
	$(GENERATOR_FILES) 	\
	$(GENERATED_FILES)

k12text_lex.h : k12text.c

ascend_scanner_lex.h : ascend_scanner.c

ascend.h: ascend.c

ascend.c: $(srcdir)/ascend.y ascend_scanner_lex.h
	$(AM_V_YACC)$(YACC) -d -p ascend -o ascend.c $(srcdir)/ascend.y

version_info.c: $(top_srcdir)/version_info.c
	$(AM_V_LN_S)$(LN_S) $< $(builddir)

checkapi:
## 'abort' checking disabled for now pending resolution of existing use of g_assert & g_error
##	$(PERL) $(top_srcdir)/tools/checkAPIs.pl -g abort -g termoutput \
	$(PERL) $(top_srcdir)/tools/checkAPIs.pl -g termoutput -build \
	-sourcedir=$(srcdir) $(NONGENERATED_C_FILES)

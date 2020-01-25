#!/usr/bin/make -f
# -*- makefile -*-
# SPDX-License-Identifier: GPL-2.0-only
# SPDX-FileCopyrightText: 2013-2016 Sven Eckelmann <sven.eckelmann@open-mesh.com>

# airtime_analyzer build
BINARY_NAME = airtime_analyzer
OBJ += airtime_analyzer.o

# airtime_analyzer flags and options
CXXFLAGS += -pedantic -Wall -W -std=gnu99 -fno-strict-aliasing -MD -MP
LDLIBS += 

# disable verbose output
ifneq ($(findstring $(MAKEFLAGS),s),s)
ifndef V
	Q_CXX = @echo '   ' CXX $@;
	Q_LD  = @echo '   ' LD  $@;
	export Q_CC
	export Q_LD
endif
endif

# standard build tools
CXX ?= g++
RM ?= rm -f
INSTALL ?= install
MKDIR ?= mkdir -p
COMPILE.cxx = $(Q_CXX)$(CXX) $(CXXFLAGS) $(CPPFLAGS) $(TARGET_ARCH) -c
LINK.o = $(Q_LD)$(CXX) $(CXXFLAGS) $(LDFLAGS) $(TARGET_ARCH)

# standard install paths
PREFIX = /usr/local
BINDIR = $(PREFIX)/bin

# try to generate revision
REVISION= $(shell	if [ -d .git ]; then \
				echo $$(git describe --always --dirty --match "v*" |sed 's/^v//' 2> /dev/null || echo "[unknown]"); \
			fi)
ifneq ($(REVISION),)
CPPFLAGS += -DSOURCE_VERSION=\"$(REVISION)\"
endif

#libpcap

CXXFLAGS += 
LDLIBS += -lpcap

# default target
all: $(BINARY_NAME)

# standard build rules
.SUFFIXES: .o .cpp
.cpp.o:
	$(COMPILE.cxx) -o $@ $<

$(BINARY_NAME): $(OBJ)
	$(LINK.o) $^ $(LDLIBS) -o $@

clean:
	$(RM) $(BINARY_NAME) $(OBJ) $(DEP)

install: $(BINARY_NAME)
	$(MKDIR) $(DESTDIR)$(SBINDIR)
	$(INSTALL) -m 0755 $(BINARY_NAME) $(DESTDIR)$(BINDIR)

# load dependencies
DEP = $(OBJ:.o=.d)
-include $(DEP)

.PHONY: all clean install

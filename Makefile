#
# Copyright (C) 2007-2011 B.A.T.M.A.N. contributors:
#
# Marek Lindner, Simon Wunderlich
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of version 2 of the GNU General Public
# License as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
# 02110-1301, USA
#



PWD:=$(shell pwd)
KERNELPATH ?= /lib/modules/$(shell uname -r)/build
# sanity check: does KERNELPATH exist?
ifeq ($(shell cd $(KERNELPATH) && pwd),)
$(warning $(KERNELPATH) is missing, please set KERNELPATH)
endif

export KERNELPATH

REVISION= $(shell	if [ -d .git ]; then \
				echo $$(git describe --always --dirty 2> /dev/null || echo "[unknown]"); \
			fi)

NUM_CPUS = $(shell nproc 2> /dev/null || echo 1)

include $(PWD)/Makefile.kbuild

all:
	$(MAKE) -C $(KERNELPATH) REVISION=$(REVISION) M=$(PWD) PWD=$(PWD) -j $(NUM_CPUS) modules

clean:
	$(MAKE) -C $(KERNELPATH) M=$(PWD) PWD=$(PWD) clean

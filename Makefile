#DCF_TOP_BUILDDIR = $(shell pwd)
$(eval DCF_TOP_BUILDDIR := $(abspath $(CURDIR)))
$(info $(DCF_TOP_BUILDDIR))
include $(DCF_TOP_BUILDDIR)/build/linux/opengauss/Makefile.global

SUBDIRS = src

# Supress parallel build to avoid depencies in the subdirectories.
.NOTPARALLEL:

$(recurse)
$(eval DCF_TOP_BUILDDIR := $(abspath $(CURDIR)/../..))
$(info $(DCF_TOP_BUILDDIR))
BASE_BUILD_PATH = $(DCF_TOP_BUILDDIR)/build/linux/opengauss
subdir = src/callback
include $(BASE_BUILD_PATH)/Makefile.global

include $(BASE_BUILD_PATH)/common.mk

OBJS=cb_func.o

all: $(OBJS)

$(OBJS):cb_func.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $^

install:all

clean:
	rm -f $(OBJS)
distclean: clean

maintainer-clean: distclean

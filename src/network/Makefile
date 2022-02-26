$(eval DCF_TOP_BUILDDIR := $(abspath $(CURDIR)/../..))
$(info $(DCF_TOP_BUILDDIR))
BASE_BUILD_PATH = $(DCF_TOP_BUILDDIR)/build/linux/opengauss
subdir = src/network
include $(BASE_BUILD_PATH)/Makefile.global

include $(BASE_BUILD_PATH)/common.mk

SOURCE=$(wildcard ./compress/*.c ./mec/*.c ./protocol/*.c)

OBJS = $(patsubst %.c,%.o,$(SOURCE))

all: $(OBJS)

$(OBJS):%.o : %.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $^ -o $@

install:all

clean:
	rm -f $(OBJS)
distclean: clean

maintainer-clean: distclean

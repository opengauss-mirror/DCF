$(eval DCF_TOP_BUILDDIR := $(abspath $(CURDIR)/../..))
$(info $(DCF_TOP_BUILDDIR))
BASE_BUILD_PATH = $(DCF_TOP_BUILDDIR)/build/linux/opengauss
subdir = src/metadata
include $(BASE_BUILD_PATH)/Makefile.global

include $(BASE_BUILD_PATH)/common.mk

SOURCE=$(wildcard ./*c)

OBJS = $(patsubst %.c,%.o,$(SOURCE))

all: $(OBJS)


$(OBJS):%.o : %.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $^

install:all

clean:
	rm -f $(OBJS)
distclean: clean

maintainer-clean: distclean

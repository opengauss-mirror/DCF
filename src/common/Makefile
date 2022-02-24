$(eval DCF_TOP_BUILDDIR := $(abspath $(CURDIR)/../..))
$(info $(DCF_TOP_BUILDDIR))
BASE_BUILD_PATH = $(DCF_TOP_BUILDDIR)/build/linux/opengauss
subdir = src/common
include $(BASE_BUILD_PATH)/Makefile.global

include $(BASE_BUILD_PATH)/common.mk

SOURCE=$(wildcard ./*c ./cm_concurrency/*.c ./cm_defines/*.c ./cm_network/*.c ./cm_protocol/*.c ./cm_security/*.c  \
./cm_struct/*.c ./cm_time/*.c ./cm_types/*.c ./cm_utils/*.c)

OBJS = $(patsubst %.c,%.o,$(SOURCE))

all: $(OBJS)

$(OBJS):%.o : %.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $^ -o $@

install:all

clean:
	rm -f $(OBJS)
distclean: clean

maintainer-clean: distclean

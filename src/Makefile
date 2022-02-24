$(eval DCF_TOP_BUILDDIR := $(abspath $(CURDIR)/..))
BASE_BUILD_PATH = $(DCF_TOP_BUILDDIR)/build/linux/opengauss

subdir = $(DCF_TOP_BUILDDIR)/src/callback \
    $(DCF_TOP_BUILDDIR)/src/common \
    $(DCF_TOP_BUILDDIR)/src/election \
    $(DCF_TOP_BUILDDIR)/src/metadata \
    $(DCF_TOP_BUILDDIR)/src/network \
    $(DCF_TOP_BUILDDIR)/src/replication \
    $(DCF_TOP_BUILDDIR)/src/storage \
    $(DCF_TOP_BUILDDIR)/src/utils \

include $(BASE_BUILD_PATH)/Makefile.global

SUBDIRS = $(DCF_TOP_BUILDDIR)/src/callback \
    $(DCF_TOP_BUILDDIR)/src/common \
    $(DCF_TOP_BUILDDIR)/src/election \
    $(DCF_TOP_BUILDDIR)/src/metadata \
    $(DCF_TOP_BUILDDIR)/src/network \
    $(DCF_TOP_BUILDDIR)/src/replication \
    $(DCF_TOP_BUILDDIR)/src/storage \
    $(DCF_TOP_BUILDDIR)/src/utils \

include $(BASE_BUILD_PATH)/common.mk

# dcf lib version
ifeq (x$(COMMIT_ID), x)
    COMMIT_ID=$(shell git rev-parse HEAD)
endif
ifeq (x$(COMPILE_TIME), x)
    COMPILE_TIME=$(shell bash -c "date \"+%Y-%m-%d %H:%M:%S\"")
endif
DD_GETLIBVERSION =dcf_get_version
DCF_LIB_VERSION_LDFLAG += -DDCF_LIB_VERSION="static char* str_DCF_LIB_VERSION=\"DCF $(BUILD_MODE) $(COMMIT_ID) compiled at $(COMPILE_TIME)\"" -DGETLIBVERSION="$(DD_GETLIBVERSION)"
$(info DCF_LIB_VERSION $(DCF_LIB_VERSION_LDFLAG))


LDFLAGS += $(addprefix -L,$(3RD_LIB_PATH))
LDFLAGS += -L${SECURE_LIB}
LDFLAGS += -L${SSL_LIB}
LDFLAGS += -L${LZ4_LIB}
LDFLAGS += -L${ZSTD_LIB}
LDFLAGS += -L${CJSON_LIB}
LIBS = -lssl -lcrypto -lcjson -llz4 -lzstd -lpthread -ldl -lrt -lm -Wl,--whole-archive -lsecurec -Wl,--no-whole-archive

OBJS = $(SUBDIROBJS) \
		dcf_interface.o \
		dcf_version.o

DESTDIR = $(DCF_TOP_BUILDDIR)/output
DEST_INC_DIR = $(DESTDIR)/include
DEST_LIB_DIR = $(DESTDIR)/lib

all: libdcf.so

libdcf.so: $(OBJS)
	$(CC) -fPIC -shared $(LDFLAGS) $(LIBS) -o libdcf.so  $(call expand_subsys, $(OBJS))
	mkdir -p $(DEST_INC_DIR) && mkdir -p $(DEST_LIB_DIR) && mv $(DCF_TOP_BUILDDIR)/src/libdcf.so $(DEST_LIB_DIR) && \
	cp $(DCF_TOP_BUILDDIR)/src/interface/dcf_interface.h $(DEST_INC_DIR)


install:all

clean:
	rm -f $(OBJS) $(DEST_LIB_DIR)/libdcf.so $(DEST_INC_DIR)/dcf_interface.h
distclean: clean

maintainer-clean: distclean

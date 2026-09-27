# Tuấn WireGuard - Makefile
# Tác giả: Tuandethuong
#
#   make            build bản phát triển (build/tuan-wg)
#   make static     build bản tĩnh musl cho Linux amd64 (build/static/tuan-wg)
#   make test       chạy kiểm thử đơn vị
#   make check      kiểm thử đơn vị + REST API
#   make deb        đóng gói .deb (dist/)
#   make dist       đóng gói .tar.gz (dist/)
#   make demo       chạy thử giao diện với dữ liệu mẫu tại http://127.0.0.1:51821

VERSION := $(shell cat VERSION 2>/dev/null || echo 0.0.0)
GIT_REV := $(shell git rev-parse --short HEAD 2>/dev/null || echo nogit)
BUILD   ?= $(GIT_REV)

CC      ?= cc
HOSTCC  ?= cc
CFLAGS  ?= -O2 -g
WARN    := -Wall -Wextra -Wshadow -Wno-unused-parameter -Wno-missing-field-initializers
CPPFLAGS += -D_GNU_SOURCE -DTWG_VERSION=\"$(VERSION)\" -DTWG_BUILD=\"$(BUILD)\" -Isrc
LDLIBS  += -pthread -lm

BUILDDIR ?= build
OBJDIR   := $(BUILDDIR)/obj
GENDIR   := build/gen
OUT      ?= $(BUILDDIR)/tuan-wg

SRC  := $(wildcard src/*.c)
HDR  := $(wildcard src/*.h)
OBJ  := $(patsubst src/%.c,$(OBJDIR)/%.o,$(SRC)) $(OBJDIR)/assets.o
WEB  := $(shell find web -type f 2>/dev/null | sort) CHANGELOG.md

.PHONY: all static test check deb dist demo clean check-version

all: $(OUT)

$(OUT): $(OBJ)
	$(CC) $(LDFLAGS) -o $@ $(OBJ) $(LDLIBS)
	@echo "==> $@ (v$(VERSION), build $(BUILD))"

$(OBJDIR):
	mkdir -p $@

# qrcodegen.c là mã của bên thứ ba: tắt bớt cảnh báo
$(OBJDIR)/qrcodegen.o: src/qrcodegen.c src/qrcodegen.h | $(OBJDIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c -o $@ $<

$(OBJDIR)/%.o: src/%.c $(HDR) VERSION | $(OBJDIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(WARN) -c -o $@ $<

$(OBJDIR)/assets.o: $(GENDIR)/assets.c src/assets.h | $(OBJDIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c -o $@ $<

$(GENDIR)/embed: tools/embed.c
	mkdir -p $(GENDIR)
	$(HOSTCC) -O2 -o $@ $<

# Nhúng giao diện web + CHANGELOG vào binary (kèm bản nén gzip)
$(GENDIR)/assets.c: $(GENDIR)/embed $(WEB)
	rm -rf $(GENDIR)/web && mkdir -p $(GENDIR)/web
	cp -r web/. $(GENDIR)/web/
	cp CHANGELOG.md $(GENDIR)/web/CHANGELOG.md
	find $(GENDIR)/web -type f ! -name '*.gz' -exec sh -c 'gzip -9 -n -c "$$1" > "$$1.gz"' _ {} \;
	$(GENDIR)/embed $@ $(GENDIR)/web $$(find $(GENDIR)/web -type f ! -name '*.gz' | sort)

# Bản tĩnh (musl) - chạy được trên mọi bản Linux amd64 (Debian 10+, Ubuntu...)
static:
	$(MAKE) BUILDDIR=build/static CC="$${MUSL_CC:-musl-gcc}" CFLAGS="-O2 -static -fno-plt" \
		LDFLAGS="-static -s" all

TEST_SRC := $(filter-out src/main.c,$(SRC))
build/test_unit: tests/test_unit.c tests/test_more.c $(TEST_SRC) $(HDR) $(GENDIR)/assets.c
	mkdir -p build
	$(CC) $(CPPFLAGS) -O1 -g -fsanitize=address,undefined $(WARN) -o $@ tests/test_unit.c tests/test_more.c \
		$(TEST_SRC) $(GENDIR)/assets.c $(LDLIBS)

test: build/test_unit
	./build/test_unit

# kiểm thử đầy đủ không cần root: đơn vị + REST API
check: test all
	tests/api_test.sh $(OUT)

deb: static
	./packaging/build-deb.sh "$(VERSION)" build/static/tuan-wg

dist: static
	./packaging/build-tar.sh "$(VERSION)" build/static/tuan-wg

demo: all
	$(OUT) serve --demo --listen 127.0.0.1

check-version:
	@echo $(VERSION)

clean:
	rm -rf build dist

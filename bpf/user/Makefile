# Copyright Authors of Cilium
# SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)

include ../../Makefile.defs

BUILD_DIR = build

MAKEFLAGS += -r

#Compilation flags
CLANG ?= clang
FLAGS := -I$(ROOT_DIR)/bpf/tests_userspace/include -I$(ROOT_DIR)/bpf/include -I$(ROOT_DIR)/bpf -I./include -O0 -g

CLANG_COMMON_FLAGS := ${FLAGS}
CLANG_COMMON_FLAGS += -gdwarf-4 #Valgrind
CLANG_COMMON_FLAGS += -Wall -Wextra -Werror -Wshadow
CLANG_COMMON_FLAGS += -Wno-address-of-packed-member
CLANG_COMMON_FLAGS += -Wno-unknown-warning-option
CLANG_COMMON_FLAGS += -Wno-gnu-variable-sized-type-not-at-end
CLANG_COMMON_FLAGS += -Wimplicit-int-conversion -Wenum-conversion
CLANG_COMMON_FLAGS += -Wimplicit-fallthrough
CLANG_COMMON_FLAGS += -Wno-unused-parameter
CLANG_COMMON_FLAGS += -Wno-unused-function

CLANG_FLAGS += ${CLANG_COMMON_FLAGS} -std=gnu99
CLANG_CXX_FLAGS += ${CLANG_COMMON_FLAGS} -Wno-extern-c-compat

CLANG_LDFLAGS = ${LDFLAGS} -lstdc++

#Check
VALGRIND ?= valgrind
VALGRIND_OPTS ?= --leak-check=full --track-origins=yes

# Directories
SRC_DIR = .
LIB_DIR = lib
BUILD_DIR = build

# Source files
LIB_C_SRC = $(wildcard $(LIB_DIR)/*.c)
LIB_CXX_SRC = $(wildcard $(LIB_DIR)/*.cc)
TEST_SRC = $(wildcard $(SRC_DIR)/unit/*.c)

# Object files
LIB_C_OBJ = $(patsubst $(LIB_DIR)/%.c,$(BUILD_DIR)/lib/%.o,$(LIB_C_SRC))
LIB_CXX_OBJ = $(patsubst $(LIB_DIR)/%.cc,$(BUILD_DIR)/lib/%.o,$(LIB_CXX_SRC))
TEST_OBJ = $(patsubst $(SRC_DIR)/unit/%.c,$(BUILD_DIR)/unit/%.o,$(TEST_SRC))

TARGETS = $(patsubst %.o, %, $(TEST_OBJ))

.PHONY: all clean

all: debug $(TARGETS)

check: $(TARGETS)
	@for t in $(TARGETS); do \
		$(VALGRIND) $(VALGRIND_OPTS) $${t}; \
	done

#Debug Makefile
debug:
	@echo "LIB_C_SRC='$(LIB_C_SRC)'"
	@echo "LIB_C_OBJ='$(LIB_C_OBJ)'"
	@echo "LIB_CXX_SRC='$(LIB_CXX_SRC)'"
	@echo "LIB_CXX_OBJ='$(LIB_CXX_OBJ)'"
	@echo "TEST_OBJ='$(TEST_OBJ)'"
	@echo "TARGETS='$(TARGETS)'"


#Test targets
$(BUILD_DIR)/unit/%: $(BUILD_DIR)/unit/%.o $(LIB_C_OBJ) $(LIB_CXX_OBJ)
	$(QUIET) ${CLANG} ${CLANG_FLAGS} ${CLANG_LDFLAGS} -o $@ $^

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c
	@mkdir -p $(dir $@)
	$(QUIET) ${CLANG} ${CLANG_FLAGS} -c $< -o $@

#Library objs
$(BUILD_DIR)/lib/%.o: $(LIB_DIR)/%.c
	@mkdir -p $(dir $@)
	$(QUIET) ${CLANG} ${CLANG_FLAGS} -c $< -o $@
$(BUILD_DIR)/lib/%.o: $(LIB_DIR)/%.cc
	@mkdir -p $(dir $@)
	$(QUIET) ${CLANG} ${CLANG_CXX_FLAGS} -c $< -o $@

# Clean up build files
clean:
	rm -rf $(BUILD_DIR)/*

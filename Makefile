TOP:=${PWD}

LDFLAGS_GLOBAL=

#.PHONY: head_links clean back update version tags cstags 
#  standard common Makefile fragment
all: all_targets

include $(TOP)/build/extra.mk

#  include relevant component Makefile fragments

dir:=$(TOP)/test
include $(dir)/test.mk

dir:=$(TOP)/cli
include $(dir)/cli.mk

dir:=$(TOP)/core
include $(dir)/core.mk

dir:=$(TOP)/lib
include $(dir)/lib.mk

dir:=$(TOP)/api
include $(dir)/api.mk

dir:=$(TOP)/plugin
include $(dir)/plugin.mk

TARGET = l7detect$(PREFIX) 

LIBS_LIST := $(LIBS_LIST) $($(TARGET)-LIBS) 

CFLAGS_LOCAL = -g -O2 -W -Wall -Wno-unused-parameter  
CFLAGS_LOCAL += $($(TARGET)-FLAGS)

CFLAGS_GLOBAL += -I$(TOP)/include 
LDFLAGS_GLOBAL += -lpthread -lpcap -ldl
include $(TOP)/build/application.mk

CLEAN_LIST += $(OBJS)
CLEAN_LIST += $(OBJS:.o=.d)
CLEAN_LIST += $(GEN_C_FILES)

all_targets:$(DYNLIB_DIR)
	for t in $(DYN_LIBS_LIST); do $(MAKE) DYNLIB=$$t application-target|| exit -1;done	

clean:
	rm -f $(TARGET) 
	rm -f $(CLEAN_LIST)

clobber: clean
	rm -rf $(OBJ_DIR)



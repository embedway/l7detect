sp              :=  $(sp).x
dirstack_$(sp)  :=  $(d)
d               :=  $(dir)

#  component specification

#dir = $(d)/threadpool
#include $(dir)/threadpool.mk

THIRD_BUILD_DIR=$(TOP)/build/obj/third

#########################begin libevent make#################################
LIBEVENT_DIR=$(THIRD_BUILD_DIR)/libevent-2.0.10-stable

ifneq ($(findstring OCTEON, $(CHIP)), )
LIBEVENT := $(LIBEVENT_DIR)/install-dir/lib/libevent_n64.a
LIBEVENT_CFLAGS := --host=mips64-octeon-linux-gnu
else
LIBEVENT := $(LIBEVENT_DIR)/install-dir/lib/libevent_i386.a
endif

LIBS_LIST   :=  $(LIBS_LIST) $(LIBEVENT)
PRE_LIST    +=  $(LIBEVENT)

$(LIBEVENT):$(LIBEVENT_DIR)
	cd $(LIBEVENT_DIR);./configure $(LIBEVENT_CFLAGS) 	 \
       --prefix=$(LIBEVENT_DIR)/install-dir; 			\
	make;make install;cp $(LIBEVENT_DIR)/install-dir/lib/libevent.a $@

$(LIBEVENT_DIR):
	mkdir -p $(THIRD_BUILD_DIR)
	tar -C $(THIRD_BUILD_DIR) -xzvf $(TOP)/lib/third/source/libevent-2.0.10-stable.tar.gz

##########################end libevent make##################################


#  standard component Makefile footer

d   :=  $(dirstack_$(sp))
sp  :=  $(basename $(sp))

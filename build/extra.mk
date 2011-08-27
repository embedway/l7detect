#USER_CONF=runtime.mk

#CPPFLAGS_GLOBAL = -I$(OCTEON_ROOT)/target/include -Iconfig
#CPPFLAGS_GLOBAL += $(OCTEON_CPPFLAGS_GLOBAL_ADD)

CFLAGS_GLOBAL = $(CPPFLAGS_GLOBAL)
CFLAGS_GLOBAL += -O2 -g -W -Wall -Wno-unused-parameter -fexceptions  -Werror
#CFLAGS_GLOBAL += $(OCTEON_CFLAGS_GLOBAL_ADD)

ASFLAGS_GLOBAL = $(CPPFLAGS_GLOBAL) -g
#ASFLAGS_GLOBAL += $(OCTEON_ASFLAGS_GLOBAL_ADD)

#LDFLAGS_GLOBAL =
#LDFLAGS_GLOBAL += $(OCTEON_LDFLAGS_GLOBAL_ADD)

#LDFLAGS_PATH = -L$(OCTEON_ROOT)/target/lib

CFLAGS_GLOBAL += $(CFLAGS_COMMON_CONFIG)
ASFLAGS_GLOBAL += $(CFLAGS_COMMON_CONFIG)

#include $(USER_CONF)

#可以在这里增加对不同编译平台采用不同编译参数以及链接参数
ifneq ($(findstring OCTEON, $(CHIP)), )
CC = mips64-octeon-linux-gnu-gcc
AR = mips64-octeon-linux-gnu-ar
LD = mips64-octeon-linux-gnu-ld
STRIP = mips64-octeon-linux-gnu-strip
OBJDUMP = mips64-octeon-linux-gnu-objdump
NM = mips64-octeon-linux-gnu-nm
else 
CC = gcc
AR = ar
LD = ld
STRIP = strip
OBJDUMP = objdump
NM = nm
endif
#  build object directory

ifneq ($(findstring OCTEON, $(CHIP)), )
RUNTIME_FLAG += -DCHIP_OCTEON
endif

ifneq ($(findstring BCM, $(CHIP)), )
RUNTIME_FLAG += -DCHIP_BCM
endif

ifneq ($(findstring X86, $(CHIP)), )
RUNTIME_FLAG += -DCHIP_X86
endif

ifneq ($(findstring PCI, $(COMM)), )
RUNTIME_FLAG += -DCOMM_PCI
endif

ifneq ($(findstring POW, $(COMM)), )
RUNTIME_FLAG += -DCOMM_POW
endif

ifneq ($(findstring NET, $(COMM)), )
RUNTIME_FLAG += -DCOMM_NET
endif

ifneq ($(findstring LINUX, $(OS)), )
RUNTIME_FLAG += -DOS_LINUX
endif

ifneq ($(findstring WINDOWS, $(OS)), )
RUNTIME_FLAG += -DOS_WINDOWS
endif

OBJ_DIR = $(TOP)/build/obj$(PREFIX)

CFLAGS_GLOBAL += $(RUNTIME_FLAG)
#  standard compile line

COMPILE = $(CC) $(CFLAGS_GLOBAL) $(CFLAGS_LOCAL) -MD -c -o $@ $<

ASSEMBLE = $(CC) $(ASFLAGS_GLOBAL) $(ASFLAGS_LOCAL) -MD -c -o $@ $<


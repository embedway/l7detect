sp              :=  $(sp).x
dirstack_$(sp)  :=  $(d)
d               :=  $(dir)

#  component specification
LIBS_NAME := flow_pde.so flow_sde.so

flow_pde.so-OBJS := flow_pde.o
flow_sde.so-OBJS := flow_sde.o
flow_pde.so-FLAGS := 
flow_sde.so-FLAGS := 


OBJS_NAME := $(foreach obj, $(addsuffix -OBJS,$(LIBS_NAME)), $($(obj)))

DYNLIBS := $(addprefix $(DYNLIB_DIR)/,$(LIBS_NAME))
OBJS_$(d)  := $(addprefix $(OBJ_DIR)/,$(OBJS_NAME))

$(OBJS_$(d)):  CFLAGS_LOCAL := -I $(TOP)/include $($(notdir $(DYNLIB))-FLAGS) 

#  standard component Makefile rules

DEPS_$(d)   :=  $(OBJS_$(d):.o=.d)

DYN_LIBS_LIST   :=  $(DYN_LIBS_LIST) $(DYNLIBS)

CLEAN_LIST := $(CLEAN_LIST) 
CLEAN_LIST += $(OBJS_$(d)) 
CLEAN_LIST += $(DEPS_$(d)) 
CLEAN_LIST += $(DYNLIBS) *~

-include $(DEPS_$(d))

$(OBJ_DIR)/%.o: $(d)/%.c 
	$(COMPILE) 

$(DYNLIB):$(OBJ_DIR)/$($(notdir $(DYNLIB))-OBJS)
	$(CC) -fPIC -shared -o $@ $^

#  standard component Makefile footer
d   :=  $(dirstack_$(sp))
sp  :=  $(basename $(sp))

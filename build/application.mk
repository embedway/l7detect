$(DYNLIB_DIR):
	mkdir $@
#  applications object suffix rule

$(OBJ_DIR)/%.o: %.c
	$(COMPILE)

$(OBJ_DIR)/%.o: %.S
	$(ASSEMBLE)

#-include $(OBJS:.o=.d)

MADE_WITH=$(shell echo "$(OBJ_DIR)/made_with-CHIP=$(CHIP),COMM=$(COMM),OS=$(OS)")
MADE_WITH_ALL = $(OBJ_DIR)/made_with-*

$(MADE_WITH):$(USER_CONF)
	@echo "#############################CHECK YOUR PARAM############################"
	@echo "CHIP=$(CHIP)"
	@echo "COMM=$(COMM)"	
	@echo "OS=$(OS)"	
	@echo "RUNTIME_FLAG=$(RUNTIME_FLAG)"
	@echo "#############################END YOUR PARAM############################"
	@echo 
#@sleep 1
	mkdir -p $(OBJ_DIR)
	rm -f $(MADE_WITH_ALL)
	touch $(MADE_WITH)

$(TARGET) $(OBJS) $(CLEAN_LIST): $(MADE_WITH)


application-target: $(PRE_LIST) $(TARGET) $(DYNLIB)

#$(TARGET).stp: $(TARGET)
#	$(STRIP) -o $(TARGET).stp $(TARGET)

$(TARGET): $(OBJS) $(LIBS_LIST)
	$(CC) $(OBJS) $(LDFLAGS_PATH) $(LIBS_LIST) $(LDFLAGS_GLOBAL) -o $@


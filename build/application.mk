$(OBJ_DIR):
	mkdir $(OBJ_DIR)
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

#  application build target

# The user decides if the build will create the cdb files for use with
# the EDB debugger or the stripped binaries used to save space and
# reduce download time by defining the EXTRA_CVMX_APPLICATION_TARGETS
# environment variable.
#
# $ setenv EXTRA_CVMX_APPLICATION_TARGETS '$(TARGET).stp $(TARGET).cdb'
#
# If the variable is not defined the build works in the usual way.

#   The user decides if the build will create archives by defining the
#   CVMX_ARCHIVE_DIRECTORY environment variable.
#   
#   $ setenv CVMX_ARCHIVE_DIRECTORY $HOME/archive
#   
#   If the variable is not defined the build works in the usual way.
#   Building will create a unique subdirectory for each OCTEON_MODEL
#   configuration.

ARCHIVE_FILES = $(TARGET) $(EXTRA_CVMX_APPLICATION_TARGETS)

archive: $(ARCHIVE_FILES)
	-@ if [ "${CVMX_ARCHIVE_DIRECTORY}" != "" ] ; then \
		mkdir -p ${CVMX_ARCHIVE_DIRECTORY}/${OCTEON_MODEL} ; \
		cp -f $(ARCHIVE_FILES) ${CVMX_ARCHIVE_DIRECTORY}/${OCTEON_MODEL}/ ; \
		chmod -R a+r ${CVMX_ARCHIVE_DIRECTORY}/${OCTEON_MODEL} ; \
	 fi ; \

application-target: $(TARGET) $(EXTRA_CVMX_APPLICATION_TARGETS) archive $(DYNLIB)

#$(TARGET).stp: $(TARGET)
#	$(STRIP) -o $(TARGET).stp $(TARGET)

$(TARGET): $(CVMX_CONFIG) $(OBJ_DIR) $(OBJS) $(LIBS_LIST)
	$(CC) $(OBJS) $(LDFLAGS_PATH) $(LIBS_LIST) $(LDFLAGS_GLOBAL) -o $@


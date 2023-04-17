CUR_DIR=$(shell pwd)
ITRUSTEE_BUILD_PATH=/opt/itrustee_sdk
include $(ITRUSTEE_BUILD_PATH)/build/mk/common.mk

# GP API LEVEL
CFLAGS += -DAPI_LEVEL=3
TARGET_IS_ARM64=y

SRC += tee_mem_ta.c
INCLUDEDIR += -I/usr/include

# set target
COBJS := $(SRC:%.c=%.o)
TARGET = $(COBJS)

sec_binary:combine
	python3 -B ${SIGNTOOL_DIR}/signtool_v3.py ${CUR_DIR} ${CUR_DIR} --privateCfg ./config_cloud.ini

combine: $(TARGET)
	$(LD) $(LDFLAGS) $(TARGET) $(EXTRAO) -o libcombine.so
	objcopy libcombine.so

%.o: %.c
	$(CC) $(CFLAGS)  $(INCLUDEDIR) -c $< -o $@

clean:
	rm -f $(COBJS) *.so *.sec

# Copyright (c) Huawei Technologies Co., Ltd. 2018-2021. All rights reserved.
CUR_DIR=$(shell pwd)
ITRUSTEE_BUILD_PATH=${CUR_DIR}/itrustee_sdk

TARGET_APP := libkta.so

APP_SOURCES := ./ktalib.c

APP_SOURCES += $(ITRUSTEE_BUILD_PATH)/src/CA/libteec_adaptor.c

APP_CFLAGS += -fstack-protector-strong -fPIC -shared

APP_CFLAGS += -I$(ITRUSTEE_BUILD_PATH)/include/CA \

APP_LDFLAGS += -ldl -lpthread

APP_LDFLAGS += -z text -z now -z relro -z noexecstack -pie -s

APP_OBJECTS := $(APP_SOURCES:.c=.o)
$(TARGET_APP): $(APP_SOURCES)
	@$(CC) $(APP_CFLAGS) -o $@ $(APP_SOURCES) $(APP_LDFLAGS)

clean:
	rm -f *.o $(TARGET_APP)

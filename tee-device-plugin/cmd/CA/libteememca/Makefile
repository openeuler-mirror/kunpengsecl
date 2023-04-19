CUR_DIR=$(shell pwd)
ITRUSTEE_BUILD_PATH=../../../../../itrustee_sdk

TARGET_LIB = libteememca.so
SRC := tee_mem_ca.c
SRC += $(ITRUSTEE_BUILD_PATH)/src/CA/libteec_adaptor.c

LIB_CFLAGS += -fstack-protector-strong -fPIC
LIB_CFLAGS += -I$(ITRUSTEE_BUILD_PATH)/include/CA

LIB_LDFLAGS += -ldl

OBJS := $(SRC:.c=.o)

$(TARGET_LIB): $(SRC)
	@$(CC) -shared $(LIB_CFLAGS) -o $@ $(SRC) $(LIB_LDFLAGS)

clean:
	rm -f *.o $(TARGET_LIB)

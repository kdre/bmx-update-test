CIRCLE_STDLIB_HOME ?= ../circle-stdlib
include $(CIRCLE_STDLIB_HOME)/Config.mk
include Config.mk

OBJ = demo.o emux_api.o font.o joy.o kbd.o keycodes.o menu.o menu_confirm_osd.o menu_reset_osd.o menu_key_binding.o menu_gpio.o menu_keyset.o menu_switch.o menu_tape_osd.o menu_timing.o menu_usb.o overlay.o raspi_util.o text.o ui.o semaphore.o

INCLUDES = -I $(CIRCLE_STDLIB_INSTALL_DIR)/include \
	   -I $(CIRCLE_STDLIB_HOME)/include \
	   -I $(CIRCLE_STDLIB_HOME)/libs/circle/addon \
	   -I $(CIRCLE_STDLIB_HOME)/libs/circle/addon/fatfs \
	   -I ../vice-3.10/src

ifeq ($(BMC64_BUILD_PROFILE),debug)
CFLAGS_FOR_TARGET += -DBMC64_DEBUG_PROFILE
CPPFLAGS_FOR_TARGET += -DBMC64_DEBUG_PROFILE
else
CFLAGS_FOR_TARGET += -DNDEBUG
CPPFLAGS_FOR_TARGET += -DNDEBUG
endif
ifneq ($(BMC64_MENU_LOG_LEVEL),)
CFLAGS_FOR_TARGET += -DBMC64_MENU_LOG_LEVEL=$(BMC64_MENU_LOG_LEVEL)
CPPFLAGS_FOR_TARGET += -DBMC64_MENU_LOG_LEVEL=$(BMC64_MENU_LOG_LEVEL)
endif

all: libbmc64common.a

%.o : %.cpp
	$(CXX_FOR_TARGET) $(INCLUDES) -c -O2 -o $@ $< $(CFLAGS_FOR_TARGET) $(CPPFLAGS_FOR_TARGET)

%.o : %.c
	$(CC_FOR_TARGET) $(INCLUDES) -c -O2 -o $@ $< $(CFLAGS_FOR_TARGET)

libbmc64common.a: $(OBJ)
	$(AR_FOR_TARGET) cr libbmc64common.a $(OBJ)
	$(RANLIB_FOR_TARGET) libbmc64common.a

clean:
	rm -rf *.o *.a

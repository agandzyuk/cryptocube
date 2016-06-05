#
# $Id: GNUmakefile,v 1.27.2.5 2009/05/22 14:24:45 gandzyuk Exp $

PROJECT_ROOT = ../..

include $(PROJECT_ROOT)/LinuxMakefile.defines

OBJ = \
	../../cryptobox/src/aes_base.o \
	../../cryptobox/src/aes_key_exchange.o \
	../../cryptobox/src/aes_package.o \
	../../cryptobox/src/enque_buffer_sender.o \
	../../cryptobox/src/gap_detector.o \
	../../cryptobox/src/otp_base.o \
	../../cryptobox/src/otp_package.o \
	../../cryptobox/src/raw_message.o \
	../../cryptobox/src/ssl_tunnel.o \
	main.o \
	test_classes.o \
	test_enque_buffer_sender.o \
	test_otp.o

SRC = \
	../../cryptobox/src/aes_base.cpp \
	../../cryptobox/src/aes_key_exchange.cpp \
	../../cryptobox/src/aes_package.cpp \
	../../cryptobox/src/enque_buffer_sender.cpp \
	../../cryptobox/src/gap_detector.cpp \
	../../cryptobox/src/otp_base.cpp \
	../../cryptobox/src/otp_package.cpp \
	../../cryptobox/src/raw_message.cpp \
	../../cryptobox/src/ssl_tunnel.cpp \
	main.cpp \
	test_classes.cpp \
	test_enque_buffer_sender.cpp \
	test_otp.cpp


LIBS = -L/usr/lib/x86_64-linux-gnu -lcrypto -lssl -lpthread

LOCAL_INCLUDE_PATH = \
	-I. \
	-I../include \
	-I$(PROJECT_ROOT)/commonlib/include \
	-I$(PROJECT_ROOT)/commonlib/src \
	-I$(PROJECT_ROOT)/cryptossl/include \
	-I$(PROJECT_ROOT)/cryptossl/src \
	-I$(PROJECT_ROOT)/cryptobox/include \
	-I$(PROJECT_ROOT)/cryptobox/src
	
#	-I$(OPENSSLDIR)/include

MAIN = ./tester
MAIN_D = ./tester_d

LOCAL_CPP_FL += -L$(PROJECT_ROOT)/commonlib/lib \
                -L$(PROJECT_ROOT)/cryptossl/lib

#                -L$(OPENSSLDIR)/usr/lib
                
CPP_FL += 

release: LOCAL_LIBS =  \
  $(PROJECT_ROOT)/cryptossl/lib/libcryptossl.a \
  $(PROJECT_ROOT)/commonlib/lib/libcommonlib.a

release: $(MAIN)

debug: LOCAL_LIBS =  \
  $(PROJECT_ROOT)/cryptossl/lib/libcryptossl_d.a \
  $(PROJECT_ROOT)/commonlib/lib/libcommonlib_d.a

debug: $(MAIN_D)

$(MAIN) $(MAIN_D): $(OBJ)
	$(C++) $(CPP_FL) -o $@ $(OBJ) $(LIBS) $(LOCAL_LIBS)

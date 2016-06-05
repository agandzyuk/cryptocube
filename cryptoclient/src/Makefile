#
# $Id: GNUmakefile,v 1.27.2.5 2009/05/22 14:24:45 gandzyuk Exp $

PROJECT_ROOT = ../..

include $(PROJECT_ROOT)/LinuxMakefile.defines

OBJ = cryptoclient.o \
mainframe.o \
user_tasks.o

SRC = cryptoclient.cpp \
mainframe.cpp \
user_tasks.cpp

LIBS = -lpthread

LOCAL_INCLUDE_PATH = \
	-I. \
	-I../include \
	-I$(PROJECT_ROOT)/commonlib/include \
	-I$(PROJECT_ROOT)/commonlib/src \
	-I$(OPENSSLDIR)/include

MAIN = ../bin/cryptoclient
MAIN_D = ../bin/cryptoclient_d

LOCAL_CPP_FL += -I$(PROJECT_ROOT)/commonlib/lib 

release: LOCAL_LIBS =  \
  $(PROJECT_ROOT)/commonlib/lib/libcommonlib.a

release: $(MAIN)

debug: LOCAL_LIBS =  \
  $(PROJECT_ROOT)/commonlib/lib/libcommonlib_d.a

debug: $(MAIN_D)

$(MAIN) $(MAIN_D): $(OBJ)
	$(C++) $(CPP_FL) -o $@ $(OBJ) $(LOCAL_LIBS) $(LIBS)

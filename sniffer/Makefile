#
# $Id: GNUmakefile,v 1.27.2.5 2009/05/22 14:24:45 gandzyuk Exp $

PROJECT_ROOT = ..

include $(PROJECT_ROOT)/LinuxMakefile.defines

OBJ = \
	main.o

SRC = \
	main.cpp

LIBS = -lrt

LOCAL_INCLUDE_PATH = \
	-I. \

MAIN = ./sniffer
MAIN_D = ./sniffer_d

release: LOCAL_LIBS =
release: $(MAIN)

debug: LOCAL_LIBS =
debug: $(MAIN_D)

$(MAIN) $(MAIN_D): $(OBJ)
	$(C++) -o $@ $(OBJ) $(LOCAL_LIBS) $(LIBS)

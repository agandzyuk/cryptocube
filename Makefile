# $Id: Makefile,v 1.12.2.1 2009/04/28 09:04:18 gandzyuk Exp $
# 

SUBDIRS = commonlib cryptossl cryptobox sniffer

TARGET_COMPILER_VERSION = 3.4.3

all debug release::
	@for i in $(SUBDIRS); do \
	    ( cd $$i && make $(LOCAL_INCLUDE_PATH) $@ ) || exit 1; \
	done

clean depend::
	@for i in $(SUBDIRS); do \
	    ( cd $$i && make $(LOCAL_INCLUDE_PATH) $@ ) || exit 1; \
	done

$(SUBDIRS)::
	@cd $@ && make $(LOCAL_INCLUDE_PATH)

linux-gnu_checkos _checkos::
	@echo Compiling on $(OSTYPE). with GCC `g++ --version`

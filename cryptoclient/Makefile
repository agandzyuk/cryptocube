# $Id: Makefile,v 1.7.2.1 2008/10/28 14:37:20 gandzyuk Exp $ 
#

SUBDIRS = src

all debug release clean depend::
	@for i in $(SUBDIRS); do \
	    (cd $$i && make depend && make $@ ) || exit 1; \
	done

$(SUBDIRS)::
	@cd $@ && make

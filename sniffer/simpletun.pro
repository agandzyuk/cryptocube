#-------------------------------------------------
#
# Project created by QtCreator 2015-04-14T11:15:08
#
#-------------------------------------------------

QT       -= core gui

TARGET = ../sniffer/simpletun
CONFIG   += console
CONFIG   -= app_bundle

TEMPLATE = app

QMAKE_CXXFLAGS_DEBUG += -D_DEBUG -Wno-c++0x-compat

#INCLUDEPATH += ./include
#INCLUDEPATH += ../commonlib/include

#LIBS += -L../commonlib/lib -lcommonlib

HEADERS += 

SOURCES += \
    ./simpletun.c

DISTFILES += \
    ../build-simpletun-Desktop-Debug/Makefile

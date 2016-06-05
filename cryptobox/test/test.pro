#-------------------------------------------------
#
# Project created by QtCreator 2015-04-14T11:41:37
#
#-------------------------------------------------

QT -= core gui

TARGET  = ../../cryptobox/test/tester
CONFIG += console
CONFIG -= app_bundle
CONFIG += openssl


INCLUDEPATH += ../include
INCLUDEPATH += ../../commonlib/include
INCLUDEPATH += ../../cryptossl/include

TEMPLATE = app

QMAKE_CXXFLAGS_DEBUG += -D_DEBUG -Wno-c++0x-compat

unix:!macx: LIBS += -L/usr/lib/x86_64-linux-gnu/ -lssl -lcrypto -lpthread
# unix:!macx: LIBS += -lcap

LIBS += -L../../commonlib/lib -L../../cryptossl/lib -lcryptossl -lcommonlib

INCLUDEPATH += /usr/include/openssl
DEPENDPATH += /usr/include/openssl

HEADERS += \
    ./*.h \
    ../include/*.h \
    ../../commonlib/include/*.h
    ../../cryptossl/include/*.h

SOURCES += \
    ../src/aes_base.cpp \
    ../src/aes_key_exchange.cpp \
    ../src/aes_package.cpp \
    ../src/enque_buffer_sender.cpp \
    ../src/gap_detector.cpp \
    ../src/otp_base.cpp \
    ../src/otp_package.cpp \
    ../src/raw_message.cpp \
    ../src/ssl_tunnel.cpp \
    ./main.cpp \
    ./test_classes.cpp \
    ./test_enque_buffer_sender.cpp \
    ./test_otp.cpp

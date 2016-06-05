#-------------------------------------------------
#
# Project created by QtCreator 2015-04-14T11:41:37
#
#-------------------------------------------------

QT -= core gui

TARGET  = ../cryptobox/bin/cryptobox
CONFIG += console
CONFIG -= app_bundle
CONFIG += openssl


INCLUDEPATH += ./include
INCLUDEPATH+= ../commonlib/include
INCLUDEPATH+= ../cryptossl/include

TEMPLATE = app

QMAKE_CXXFLAGS_DEBUG += -D_DEBUG -Wno-c++0x-compat

unix:!macx: LIBS += -L/usr/lib/x86_64-linux-gnu/ -lssl -lcrypto -lrt
# unix:!macx: LIBS += -lcap

LIBS += -L../commonlib/lib -L../cryptossl/lib -lcommonlib -lcryptossl

INCLUDEPATH += /usr/include/openssl
DEPENDPATH += /usr/include/openssl

HEADERS += \
    include/*.h \
    ../commonlib/include/*.h \
    ../cryptossl/include/*.h

SOURCES += \
    src/aes_base.cpp \
    src/aes_key_exchange.cpp \
    src/aes_package.cpp \
    src/arp_package.cpp \
    src/configuration.cpp \
    src/cryptobox.cpp \
    src/enque_buffer_sender.cpp \
    src/ethernet_frame.cpp \
    src/gap_detector.cpp \
    src/gateway.cpp \
    src/gateway_policy.cpp \
    src/ip_package.cpp \
    src/ip6_package.cpp \
    src/otp_base.cpp \
    src/otp_package.cpp \
    src/raw_message.cpp \
    src/ssl_tunnel.cpp \
    src/statistics.cpp \
    src/tcp_connection.cpp \
    src/tunconnection.cpp \
    src/tundevice.cpp

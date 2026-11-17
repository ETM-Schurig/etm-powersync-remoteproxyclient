include(../../nymea-remoteproxy.pri)

QT -= websockets
TEMPLATE = app
TARGET = etm-powersync-boxcert-check

CONFIG += link_pkgconfig
PKGCONFIG += libcrypto

HEADERS += boxidentity.h
SOURCES += boxidentity.cpp main.cpp

target.path = /usr/bin
INSTALLS += target

include(../../nymea-remoteproxy.pri)

QT -= websockets
CONFIG += testcase
QT += testlib

TARGET = etm-powersync-boxcert-check-tests
DEFINES += BOXCERT_CHECK=\\\"$$top_builddir/tools/boxcert-check/etm-powersync-boxcert-check\\\"
DEFINES += SOURCE_DIR=\\\"$$top_srcdir\\\"

SOURCES += boxcertchecktests.cpp

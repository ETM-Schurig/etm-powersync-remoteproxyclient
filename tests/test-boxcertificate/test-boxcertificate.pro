include(../../nymea-remoteproxy.pri)

CONFIG += testcase
QT += testlib

TARGET = etm-powersync-remoteproxyclient-tests

INCLUDEPATH += $$top_srcdir/libnymea-remoteproxyclient
LIBS += -L$$top_builddir/libnymea-remoteproxyclient/ -lnymea-remoteproxyclient
# The library under test, not an installed libnymea-remoteproxyclient. RPATH, not RUNPATH: the
# target_wrapper.sh of make check sets LD_LIBRARY_PATH to the system library directory.
QMAKE_RPATHDIR += $$top_builddir/libnymea-remoteproxyclient
QMAKE_LFLAGS += -Wl,--disable-new-dtags

SOURCES += boxcertificatetests.cpp

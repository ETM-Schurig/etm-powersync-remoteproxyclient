include(../common/common.pri)

INCLUDEPATH += $$PWD

# ETM: OpenSSL checks that the box key belongs to its certificate.
CONFIG += link_pkgconfig
PKGCONFIG += libcrypto

# Directory of box.crt and box.key, set by the packaging (qmake BOX_CERTIFICATE_DIR=...). Unset:
# no box certificate unless REMOTEPROXYCLIENT_CERTIFICATE_DIR is set at run time.
!isEmpty(BOX_CERTIFICATE_DIR): DEFINES += BOX_CERTIFICATE_DIR=\\\"$$BOX_CERTIFICATE_DIR\\\"

HEADERS += \
    $$PWD/tunnelproxy/tunnelproxyremoteconnection.h \
    $$PWD/boxcertificate.h \
    $$PWD/tunnelproxy/tunnelproxysocket.h \
    $$PWD/tunnelproxy/tunnelproxysocketserver.h \
    $$PWD/tcpsocketconnection.h \
    $$PWD/proxyjsonrpcclient.h \
    $$PWD/jsonreply.h \
    $$PWD/proxyconnection.h \
    $$PWD/websocketconnection.h

SOURCES += \
    $$PWD/tunnelproxy/tunnelproxyremoteconnection.cpp \
    $$PWD/boxcertificate.cpp \
    $$PWD/tunnelproxy/tunnelproxysocket.cpp \
    $$PWD/tunnelproxy/tunnelproxysocketserver.cpp \
    $$PWD/tcpsocketconnection.cpp \
    $$PWD/proxyjsonrpcclient.cpp \
    $$PWD/jsonreply.cpp \
    $$PWD/proxyconnection.cpp \
    $$PWD/websocketconnection.cpp


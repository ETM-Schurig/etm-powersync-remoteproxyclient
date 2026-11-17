include(nymea-remoteproxy.pri)

# ETM-PowerSync: only the client library is built here (the relay lives in
# etm-powersync-remote-proxy).
SERVER_NAME=etm-powersync-remoteproxyclient

# Parse and export SERVER_VERSION
SERVER_VERSION=$$system('dpkg-parsechangelog | sed -n -e "s/^Version: //p"')

TEMPLATE=subdirs
SUBDIRS += libnymea-remoteproxyclient boxcert-check
boxcert-check.subdir = tools/boxcert-check

!disabletests {
    SUBDIRS += tests
}

tests.depends = libnymea-remoteproxyclient boxcert-check

message("----------------------------------------------------------")
message("Building etm-powersync-remoteproxyclient $${SERVER_VERSION}")
message("----------------------------------------------------------")
message("Qt version:" $$[QT_VERSION])

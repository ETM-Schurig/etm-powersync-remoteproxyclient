// SPDX-License-Identifier: LGPL-3.0-or-later

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
*
* etm-powersync-remoteproxyclient
* Client library of the ETM-PowerSync remote proxy, based on nymea-remoteproxy
*
* Copyright (C) 2026, ETM-Schurig SARL
*
* This library is free software: you can redistribute it and/or
* modify it under the terms of the GNU Lesser General Public License
* as published by the Free Software Foundation, either version 3
* of the License, or (at your option) any later version.
*
* This library is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
* GNU Lesser General Public License for more details.
*
* You should have received a copy of the GNU Lesser General Public License
* along with this library. If not, see <https://www.gnu.org/licenses/>.
*
* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#include "boxcertificate.h"
#include "tcpsocketconnection.h"

#include <QDir>
#include <QFile>
#include <QProcess>
#include <QSignalSpy>
#include <QSslServer>
#include <QTemporaryDir>
#include <QtTest>

#include <unistd.h>

using namespace remoteproxyclient;

static QStringList s_log;
static QtMessageHandler s_previousHandler = nullptr;

static void captureHandler(QtMsgType type, const QMessageLogContext &context, const QString &message)
{
    Q_UNUSED(type)
    Q_UNUSED(context)
    s_log.append(message);
}

class BoxCertificateTests : public QObject
{
    Q_OBJECT

private:
    QTemporaryDir m_dir;
    QString path(const QString &name) const { return m_dir.filePath(name); }
    bool openssl(const QStringList &arguments);
    bool makeCase(const QString &name, const QString &certificate, const QString &key);

    // Connects the library to a local TLS server and returns what the server saw.
    QSslCertificate presentedCertificate(bool *connected);

private slots:
    void initTestCase();

    void connection_data();
    void connection();

    void unreadableFile();
    void noKeyContentInLog();
};

bool BoxCertificateTests::openssl(const QStringList &arguments)
{
    QProcess process;
    process.setProcessChannelMode(QProcess::MergedChannels);
    process.start("openssl", arguments);
    if (!process.waitForFinished(30000) || process.exitCode() != 0) {
        qWarning() << "openssl" << arguments << process.readAll();
        return false;
    }
    return true;
}

bool BoxCertificateTests::makeCase(const QString &name, const QString &certificate, const QString &key)
{
    QDir().mkpath(path(name));
    if (!certificate.isEmpty() && !QFile::copy(path(certificate), path(name + "/box.crt")))
        return false;
    if (!key.isEmpty() && !QFile::copy(path(key), path(name + "/box.key")))
        return false;
    return true;
}

void BoxCertificateTests::initTestCase()
{
    QVERIFY(m_dir.isValid());
    const QStringList ec = {"-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes"};
    const QString uuid = QUuid::createUuid().toString(QUuid::WithoutBraces);

    // Test CA, the box, a second key, and the TLS server standing for the relay.
    QVERIFY(openssl(QStringList({"req", "-x509", "-days", "1", "-subj", "/CN=Test box CA"}) + ec
                    + QStringList({"-addext", "basicConstraints=critical,CA:TRUE", "-keyout", path("ca.key"), "-out", path("ca.crt")})));
    QVERIFY(openssl(QStringList({"req", "-subj", "/CN=" + uuid}) + ec + QStringList({"-keyout", path("box.key"), "-out", path("box.csr")})));
    QVERIFY(openssl({"x509", "-req", "-days", "1", "-in", path("box.csr"), "-CA", path("ca.crt"), "-CAkey", path("ca.key"),
                     "-CAcreateserial", "-out", path("box.crt")}));
    QVERIFY(openssl({"x509", "-req", "-not_before", "20200101000000Z", "-not_after", "20200102000000Z", "-in", path("box.csr"),
                     "-CA", path("ca.crt"), "-CAkey", path("ca.key"), "-CAcreateserial", "-out", path("expired.crt")}));
    QVERIFY(openssl(QStringList({"req", "-subj", "/CN=other"}) + ec + QStringList({"-keyout", path("other.key"), "-out", path("other.csr")})));
    QVERIFY(openssl(QStringList({"req", "-x509", "-days", "1", "-subj", "/CN=127.0.0.1"}) + ec
                    + QStringList({"-keyout", path("server.key"), "-out", path("server.crt")})));

    QFile garbage(path("garbage"));
    QVERIFY(garbage.open(QIODevice::WriteOnly));
    garbage.write("not a PEM file\n");
    garbage.close();

    QVERIFY(makeCase("missing", "", ""));
    QVERIFY(makeCase("missing-key", "box.crt", ""));
    QVERIFY(makeCase("unparsable", "box.crt", "garbage"));
    QVERIFY(makeCase("mismatch", "box.crt", "other.key"));
    QVERIFY(makeCase("expired", "expired.crt", "box.key"));
    QVERIFY(makeCase("valid", "box.crt", "box.key"));
}

QSslCertificate BoxCertificateTests::presentedCertificate(bool *connected)
{
    QFile certificateFile(path("server.crt"));
    QFile keyFile(path("server.key"));
    certificateFile.open(QIODevice::ReadOnly);
    keyFile.open(QIODevice::ReadOnly);
    QSslConfiguration configuration = QSslConfiguration::defaultConfiguration();
    configuration.setLocalCertificate(QSslCertificate(certificateFile.readAll()));
    configuration.setPrivateKey(QSslKey(keyFile.readAll(), QSsl::Ec));
    // Like the relay on its TCP port: ask for a client certificate, do not require one.
    configuration.setPeerVerifyMode(QSslSocket::QueryPeer);

    QSslServer server;
    server.setSslConfiguration(configuration);
    connect(&server, &QSslServer::sslErrors, this, [](QSslSocket *socket, const QList<QSslError> &) {
        socket->ignoreSslErrors();
    });
    QSslCertificate seen;
    bool encrypted = false;
    connect(&server, &QSslServer::pendingConnectionAvailable, this, [&]() {
        // QSslServer hands the socket over once the handshake is done.
        QSslSocket *socket = qobject_cast<QSslSocket *>(server.nextPendingConnection());
        seen = socket->peerCertificate();
        encrypted = socket->isEncrypted();
    });
    if (!server.listen(QHostAddress::LocalHost, 0))
        return QSslCertificate();

    TcpSocketConnection connection;
    connect(&connection, &ProxyConnection::sslErrors, &connection, [&connection](const QList<QSslError> &) {
        connection.ignoreSslErrors();
    });
    connection.connectServer(QUrl(QString("ssl://127.0.0.1:%1").arg(server.serverPort())));
    *connected = QTest::qWaitFor([&]() { return encrypted && connection.connected(); }, 5000);

    connection.disconnectServer();
    return seen;
}

void BoxCertificateTests::connection_data()
{
    QTest::addColumn<QString>("caseName");
    QTest::addColumn<bool>("presented");

    QTest::newRow("absent") << "missing" << false;
    QTest::newRow("key absent") << "missing-key" << false;
    QTest::newRow("unreadable") << "unparsable" << false;
    QTest::newRow("key does not match") << "mismatch" << false;
    QTest::newRow("expired") << "expired" << false;
    QTest::newRow("valid") << "valid" << true;
}

void BoxCertificateTests::connection()
{
    QFETCH(QString, caseName);
    QFETCH(bool, presented);

    qputenv("REMOTEPROXYCLIENT_CERTIFICATE_DIR", path(caseName).toLocal8Bit());
    s_log.clear();
    s_previousHandler = qInstallMessageHandler(captureHandler);
    bool connected = false;
    const QSslCertificate seen = presentedCertificate(&connected);
    qInstallMessageHandler(s_previousHandler);

    // Never blocks: the connection is up in every case, with or without the certificate.
    QVERIFY(connected);
    if (presented) {
        QFile certificateFile(path("box.crt"));
        QVERIFY(certificateFile.open(QIODevice::ReadOnly));
        QCOMPARE(seen, QSslCertificate(certificateFile.readAll()));
    } else {
        QVERIFY(seen.isNull());
    }

    // One warning per connection attempt without a usable certificate, none with one.
    int warnings = 0;
    foreach (const QString &line, s_log)
        warnings += line.contains("Connecting without box certificate") ? 1 : 0;
    QCOMPARE(warnings, presented ? 0 : 1);
}

void BoxCertificateTests::unreadableFile()
{
    if (geteuid() == 0)
        QSKIP("root reads any file");

    QVERIFY(makeCase("no-permission", "box.crt", "box.key"));
    QVERIFY(QFile::setPermissions(path("no-permission/box.key"), QFileDevice::Permissions()));
    QSslCertificate certificate;
    QSslKey key;
    QString detail;
    QCOMPARE(BoxCertificate::load(path("no-permission"), &certificate, &key, &detail), BoxCertificate::Unreadable);
    QVERIFY(certificate.isNull());

    qputenv("REMOTEPROXYCLIENT_CERTIFICATE_DIR", path("no-permission").toLocal8Bit());
    s_previousHandler = qInstallMessageHandler(captureHandler);
    bool connected = false;
    const QSslCertificate seen = presentedCertificate(&connected);
    qInstallMessageHandler(s_previousHandler);
    QVERIFY(connected);
    QVERIFY(seen.isNull());
}

void BoxCertificateTests::noKeyContentInLog()
{
    QFile keyFile(path("box.key"));
    QVERIFY(keyFile.open(QIODevice::ReadOnly));
    const QList<QByteArray> keyLines = keyFile.readAll().split('\n');

    s_log.clear();
    for (const QString &caseName : {QString("valid"), QString("mismatch"), QString("unparsable")}) {
        qputenv("REMOTEPROXYCLIENT_CERTIFICATE_DIR", path(caseName).toLocal8Bit());
        QLoggingCategory::setFilterRules("RemoteProxyClientTcpSocket.debug=true");
        s_previousHandler = qInstallMessageHandler(captureHandler);
        bool connected = false;
        presentedCertificate(&connected);
        qInstallMessageHandler(s_previousHandler);
        QLoggingCategory::setFilterRules(QString());
    }

    QVERIFY(!s_log.isEmpty());
    foreach (const QString &line, s_log) {
        QVERIFY2(!line.contains("PRIVATE KEY"), qPrintable(line));
        foreach (const QByteArray &keyLine, keyLines) {
            if (keyLine.size() > 16 && !keyLine.startsWith("-----"))
                QVERIFY2(!line.contains(QString::fromLatin1(keyLine)), "key material in the log");
        }
    }
}

QTEST_MAIN(BoxCertificateTests)
#include "boxcertificatetests.moc"

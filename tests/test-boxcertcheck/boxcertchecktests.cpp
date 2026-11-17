// SPDX-License-Identifier: LGPL-3.0-or-later
// Copyright (C) 2026, ETM-Schurig SARL

#include <QDir>
#include <QFile>
#include <QProcess>
#include <QTemporaryDir>
#include <QUuid>
#include <QtTest>

// etm-powersync-boxcert-check against certificates made like the enrolment would, and every way
// to get it wrong. The certificates are those of the relay tests (etm-powersync-remote-proxy,
// tests/test-etm, makeBoxPki), with the same expected verdicts and reasons.
class BoxCertCheckTests : public QObject
{
    Q_OBJECT

private:
    QTemporaryDir m_dir;
    // Invented test namespace, the one of the relay tests and of deploy/essai/pki-essai.sh.
    const QUuid m_namespace = QUuid("6b2f0d3c-0000-4000-8000-00000000e55a");
    QUuid m_boxA;
    QUuid m_boxB;

    QString path(const QString &name) const { return m_dir.filePath(name); }
    bool openssl(const QStringList &arguments);
    bool makeCertificate(const QString &name, const QString &subject, const QString &ca, const QString &extensions,
                         const QStringList &validity = {"-days", "1"});
    int check(const QStringList &arguments, QString *output);

private slots:
    void initTestCase();
    void verdict_data();
    void verdict();
    void usageErrors();
    void ruleIdenticalToRelay();
};

bool BoxCertCheckTests::openssl(const QStringList &arguments)
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

bool BoxCertCheckTests::makeCertificate(const QString &name, const QString &subject, const QString &ca, const QString &extensions,
                                        const QStringList &validity)
{
    QFile extensionFile(path(name + ".ext"));
    if (!extensionFile.open(QIODevice::WriteOnly))
        return false;
    extensionFile.write(extensions.toLatin1());
    extensionFile.close();
    return openssl({"req", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-subj", subject,
                    "-keyout", path(name + ".key"), "-out", path(name + ".csr")})
            && openssl(QStringList({"x509", "-req"}) + validity + QStringList({"-in", path(name + ".csr"), "-CA", path(ca + ".crt"),
                       "-CAkey", path(ca + ".key"), "-CAcreateserial", "-extfile", path(name + ".ext"), "-out", path(name + ".crt")}))
            && QFile::setPermissions(path(name + ".key"), QFileDevice::ReadOwner | QFileDevice::WriteOwner);
}

int BoxCertCheckTests::check(const QStringList &arguments, QString *output)
{
    QProcess process;
    process.setProcessChannelMode(QProcess::MergedChannels);
    process.start(BOXCERT_CHECK, arguments);
    process.waitForFinished(30000);
    *output = QString::fromUtf8(process.readAll()).trimmed();
    return process.exitStatus() == QProcess::NormalExit ? process.exitCode() : -1;
}

void BoxCertCheckTests::initTestCase()
{
    QVERIFY(m_dir.isValid());
    // Shared test vector: the relay tests and pki-essai.sh (Python uuid5) give the same UUID.
    QCOMPARE(QUuid::createUuidV5(m_namespace, QByteArray("ESSAI-0001")), QUuid("9a6c3dcb-4dc6-5ee1-9779-eef66f4dec39"));
    m_boxA = QUuid::createUuidV5(m_namespace, QByteArray("ESSAI-A"));
    m_boxB = QUuid::createUuidV5(m_namespace, QByteArray("ESSAI-B"));

    // Two levels, as the real ETM CA: an offline root, and the box intermediate "ca" which alone
    // goes into ca.crt on the box. "other" is another intermediate of the same root, "rogue" a
    // foreign CA.
    for (const QString &ca : {QString("root"), QString("rogue")}) {
        QVERIFY(openssl({"req", "-x509", "-days", "1", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
                         "-subj", "/CN=ETM test " + ca, "-addext", "basicConstraints=critical,CA:TRUE",
                         "-addext", "keyUsage=critical,keyCertSign,cRLSign", "-keyout", path(ca + ".key"), "-out", path(ca + ".crt")}));
    }
    for (const QString &ca : {QString("ca"), QString("other")}) {
        QVERIFY(makeCertificate(ca, "/CN=ETM test intermediate " + ca, "root",
                                "basicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign\n"));
    }

    // name, subject, signing CA, SAN URIs, extensions if not the box profile (see README.ETM.md).
    const QString profile = "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=clientAuth\n";
    auto sanDer = [](const QString &uri) {
        // GeneralNames: SEQUENCE { [6] IA5String uri }, short lengths only.
        const QByteArray name = QByteArray("\x86") + char(uri.size()) + uri.toLatin1();
        return QString("subjectAltName=DER:%1\n").arg(QString::fromLatin1((QByteArray("\x30") + char(name.size()) + name).toHex()));
    };
    const QString a = m_boxA.toString(QUuid::WithoutBraces);
    const QString b = m_boxB.toString(QUuid::WithoutBraces);
    const QList<QStringList> boxes = {
        {"boxA", "/CN=" + a + "/serialNumber=ESSAI-A", "ca", "urn:uuid:" + a},
        {"boxB", "/CN=" + b + "/serialNumber=ESSAI-B", "ca", "urn:uuid:" + b},
        {"rogueA", "/CN=" + a + "/serialNumber=ESSAI-A", "rogue", "urn:uuid:" + a},
        {"otherA", "/CN=" + a + "/serialNumber=ESSAI-A", "other", "urn:uuid:" + a},
        {"upperA", "/serialNumber=ESSAI-A", "ca", "URN:UUID:" + a.toUpper()},
        {"cnB", "/CN=" + b + "/serialNumber=ESSAI-A", "ca", "urn:uuid:" + a},
        {"twoSan", "/CN=" + a + "/serialNumber=ESSAI-A", "ca", "urn:uuid:" + a + ",URI:urn:uuid:" + b},
        {"cnOnly", "/CN=" + a + "/serialNumber=ESSAI-A", "ca", ""},
        {"noSerial", "/CN=" + a, "ca", "urn:uuid:" + a},
        {"wrongSerial", "/CN=" + a + "/serialNumber=ESSAI-X", "ca", "urn:uuid:" + a},
        {"caTrueA", "/CN=" + a + "/serialNumber=ESSAI-A", "ca", "urn:uuid:" + a,
         "basicConstraints=critical,CA:TRUE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=clientAuth\n"},
        {"noExtensionsA", "/CN=" + a + "/serialNumber=ESSAI-A", "ca", "urn:uuid:" + a, "\n"},
        {"bcNotCriticalA", "/CN=" + a + "/serialNumber=ESSAI-A", "ca", "urn:uuid:" + a,
         "basicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=clientAuth\n"},
        {"keyAgreementA", "/CN=" + a + "/serialNumber=ESSAI-A", "ca", "urn:uuid:" + a,
         "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,keyAgreement\nextendedKeyUsage=clientAuth\n"},
        {"noKeyUsageA", "/CN=" + a + "/serialNumber=ESSAI-A", "ca", "urn:uuid:" + a,
         "basicConstraints=critical,CA:FALSE\nextendedKeyUsage=clientAuth\n"},
        {"serverAuthA", "/CN=" + a + "/serialNumber=ESSAI-A", "ca", "urn:uuid:" + a,
         "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\n"},
        {"noEkuA", "/CN=" + a + "/serialNumber=ESSAI-A", "ca", "urn:uuid:" + a,
         "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\n"},
        {"pathlenA", "/CN=" + a + "/serialNumber=ESSAI-A", "ca", "urn:uuid:" + a,
         "basicConstraints=critical,CA:FALSE,pathlen:0\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=clientAuth\n"},
        {"sanSuffixA", "/CN=" + a + "/serialNumber=ESSAI-A", "ca", "urn:uuid:" + a + "x"},
        {"sanBracesA", "/CN=" + a + "/serialNumber=ESSAI-A", "ca", "urn:uuid:{" + a + "}"},
        {"sanTruncatedA", "/CN=" + a + "/serialNumber=ESSAI-A", "ca", "urn:uuid:" + a.left(35)},
        {"sanPlusMalformedA", "/CN=" + a + "/serialNumber=ESSAI-A", "ca", "urn:uuid:" + a + ",URI:urn:uuid:" + a + "x"},
        {"sanFinalLineFeedA", "/CN=" + a + "/serialNumber=ESSAI-A", "ca", "", profile + sanDer("urn:uuid:" + a + "\n")},
        {"sanInitialLineFeedA", "/CN=" + a + "/serialNumber=ESSAI-A", "ca", "", profile + sanDer("urn:uuid:\n" + a)},
        {"sanInnerLineFeedA", "/CN=" + a + "/serialNumber=ESSAI-A", "ca", "", profile + sanDer("urn:uuid:" + a.left(18) + "\n" + a.mid(18))},
    };
    for (const QStringList &box : boxes) {
        const QString extensions = (box.count() > 4 ? box.at(4) : profile)
                + (box.at(3).isEmpty() ? QString() : "subjectAltName=URI:" + box.at(3) + "\n");
        QVERIFY2(makeCertificate(box.at(0), box.at(1), box.at(2), extensions), qPrintable(box.at(0)));
    }
    const QString boxAExtensions = profile + "subjectAltName=URI:urn:uuid:" + a + "\n";
    QVERIFY(makeCertificate("expiredA", "/CN=" + a + "/serialNumber=ESSAI-A", "ca", boxAExtensions,
                            {"-not_before", "20200101000000Z", "-not_after", "20200102000000Z"}));
    QVERIFY(makeCertificate("futureA", "/CN=" + a + "/serialNumber=ESSAI-A", "ca", boxAExtensions,
                            {"-not_before", "20990101000000Z", "-not_after", "20990102000000Z"}));

    // A self-signed certificate that claims box A.
    QVERIFY(openssl({"req", "-x509", "-days", "1", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
                     "-subj", "/CN=" + a + "/serialNumber=ESSAI-A", "-addext", "basicConstraints=critical,CA:FALSE",
                     "-addext", "keyUsage=critical,digitalSignature", "-addext", "extendedKeyUsage=clientAuth",
                     "-addext", "subjectAltName=URI:urn:uuid:" + a, "-keyout", path("selfA.key"), "-out", path("selfA.crt")}));

    // A CA file holding leaves instead of a CA.
    QFile leaves(path("leaves.pem"));
    QVERIFY(leaves.open(QIODevice::WriteOnly));
    for (const QString &name : {QString("selfA.crt"), QString("boxA.crt")}) {
        QFile certificate(path(name));
        QVERIFY(certificate.open(QIODevice::ReadOnly));
        leaves.write(certificate.readAll());
    }
    leaves.close();

    QFile revoked(path("revoked.txt"));
    QVERIFY(revoked.open(QIODevice::WriteOnly));
    QProcess fingerprint;
    fingerprint.start("openssl", {"x509", "-in", path("boxA.crt"), "-noout", "-fingerprint", "-sha256"});
    QVERIFY(fingerprint.waitForFinished(30000));
    revoked.write("# test\n" + fingerprint.readAll().split('=').last());
    revoked.close();

    QVERIFY(QFile::copy(path("boxA.key"), path("open.key")));
    QVERIFY(QFile::setPermissions(path("open.key"), QFileDevice::ReadOwner | QFileDevice::WriteOwner | QFileDevice::ReadOther));
    QFile empty(path("empty.crt"));
    QVERIFY(empty.open(QIODevice::WriteOnly));
    empty.close();
}

void BoxCertCheckTests::verdict_data()
{
    QTest::addColumn<QString>("certificate");
    QTest::addColumn<QString>("ca");
    QTest::addColumn<QString>("box");
    QTest::addColumn<QStringList>("extra");
    QTest::addColumn<int>("exitCode");
    QTest::addColumn<QString>("message");

    const QString notSigned = "not signed by the box CA (not signed by the box CA (unable to get local issuer certificate))";
    const QString malformed = "issued for another box (SAN urn:uuid is not a UUID (36 characters 8-4-4-4-12, no braces))";

    // The enrolled box: ca.crt holds the box intermediate only, the chain stops there.
    QTest::newRow("enrolled box, partial chain") << "boxA" << "ca" << "A" << QStringList() << 0 << "ACCEPTED";
    QTest::newRow("enrolled box, key checked") << "boxA" << "ca" << "A" << QStringList({"--key", "boxA.key"}) << 0 << "ACCEPTED";

    // Chain (relay: boxCertificateChain, boxCertificateChainDiagnostic).
    QTest::newRow("foreign CA") << "rogueA" << "ca" << "A" << QStringList() << 1 << notSigned;
    QTest::newRow("other intermediate of the same root") << "otherA" << "ca" << "A" << QStringList() << 1 << notSigned;
    QTest::newRow("self-signed") << "selfA" << "ca" << "A" << QStringList() << 1 << "not signed by the box CA (self-signed)";
    QTest::newRow("root alone as CA") << "boxA" << "root" << "A" << QStringList() << 1 << notSigned;
    QTest::newRow("leaves as CA, self-signed") << "selfA" << "leaves" << "A" << QStringList() << 1 << "not signed by the box CA";
    QTest::newRow("leaves as CA, the leaf itself")
            << "boxA" << "leaves" << "A" << QStringList() << 1 << "not signed by the box CA (the certificate itself is in box-ca.pem)";
    QTest::newRow("the intermediate itself") << "ca" << "ca" << "A" << QStringList() << 1
                                             << "not a box certificate (basicConstraints CA:TRUE, a box certificate is never a CA)";
    QTest::newRow("expired") << "expiredA" << "ca" << "A" << QStringList() << 1 << "not signed by the box CA (certificate expired)";
    QTest::newRow("not yet valid") << "futureA" << "ca" << "A" << QStringList() << 1 << "not signed by the box CA (certificate not yet valid)";

    // Profile (relay: boxCertificateProfile).
    const QList<QPair<QString, QString>> profiles = {
        {"caTrueA", "basicConstraints CA:TRUE, a box certificate is never a CA"},
        {"noExtensionsA", "no critical basicConstraints CA:FALSE"},
        {"bcNotCriticalA", "no critical basicConstraints CA:FALSE"},
        {"keyAgreementA", "no keyUsage digitalSignature"},
        {"noKeyUsageA", "no keyUsage digitalSignature"},
        {"serverAuthA", "no extendedKeyUsage clientAuth"},
        {"noEkuA", "no extendedKeyUsage clientAuth"},
        {"pathlenA", "basicConstraints with a pathLenConstraint, a box certificate is never a CA"},
    };
    for (const auto &profile : profiles)
        QTest::newRow(qPrintable(profile.first)) << profile.first << "ca" << "A" << QStringList() << 1 << "not a box certificate (" + profile.second + ")";

    // Identity (relay: boxCertificateIdentity).
    QTest::newRow("box A for box B") << "boxA" << "ca" << "B" << QStringList() << 1 << "issued for another box (SAN urn:uuid is another UUID)";
    QTest::newRow("UUID in capitals") << "upperA" << "ca" << "A" << QStringList() << 0 << "ACCEPTED";
    QTest::newRow("CN of box B, for box A") << "cnB" << "ca" << "A" << QStringList() << 0 << "ACCEPTED";
    QTest::newRow("CN of box B, for box B") << "cnB" << "ca" << "B" << QStringList() << 1 << "issued for another box";
    QTest::newRow("CN only") << "cnOnly" << "ca" << "A" << QStringList() << 1 << "issued for another box (0 SAN urn:uuid, exactly one expected)";
    QTest::newRow("two SAN, box A") << "twoSan" << "ca" << "A" << QStringList() << 1 << "issued for another box (2 SAN urn:uuid, exactly one expected)";
    QTest::newRow("two SAN, box B") << "twoSan" << "ca" << "B" << QStringList() << 1 << "issued for another box (2 SAN urn:uuid, exactly one expected)";
    QTest::newRow("no serialNumber") << "noSerial" << "ca" << "A" << QStringList() << 1
                                     << "issued for another box (exactly one non-empty serialNumber expected in the subject)";
    QTest::newRow("serialNumber of another box") << "wrongSerial" << "ca" << "A" << QStringList() << 1
                                                 << "issued for another box (the UUID is not UUIDv5(ETM namespace, serialNumber))";
    QTest::newRow("another namespace") << "boxA" << "ca" << "A" << QStringList({"--namespace", QUuid::createUuid().toString(QUuid::WithoutBraces)})
                                       << 1 << "issued for another box (the UUID is not UUIDv5(ETM namespace, serialNumber))";
    for (const QString &name : {QString("sanSuffixA"), QString("sanBracesA"), QString("sanTruncatedA"),
                                QString("sanFinalLineFeedA"), QString("sanInitialLineFeedA"), QString("sanInnerLineFeedA")})
        QTest::newRow(qPrintable(name)) << name << "ca" << "A" << QStringList() << 1 << malformed;
    QTest::newRow("sanPlusMalformedA") << "sanPlusMalformedA" << "ca" << "A" << QStringList() << 1
                                       << "issued for another box (2 SAN urn:uuid, exactly one expected)";

    // The checks of the tool after the rule of the relay.
    QTest::newRow("no certificate") << "empty" << "ca" << "A" << QStringList() << 1 << "REFUSED: no certificate";
    QTest::newRow("revoked") << "boxA" << "ca" << "A" << QStringList({"--revoked", "revoked.txt"}) << 1 << "REFUSED: revoked";
    QTest::newRow("other serial") << "boxA" << "ca" << "A" << QStringList({"--serial", "ESSAI-B"}) << 1 << "serialNumber";
    QTest::newRow("key of another box") << "boxA" << "ca" << "A" << QStringList({"--key", "boxB.key"}) << 1 << "does not belong";
    QTest::newRow("key readable by others") << "boxA" << "ca" << "A" << QStringList({"--key", "open.key"}) << 1 << "0600";
}

void BoxCertCheckTests::verdict()
{
    QFETCH(QString, certificate);
    QFETCH(QString, ca);
    QFETCH(QString, box);
    QFETCH(QStringList, extra);
    QFETCH(int, exitCode);
    QFETCH(QString, message);

    QStringList arguments = {"--cert", path(certificate + ".crt"), "--ca", path(ca + (ca == "leaves" ? ".pem" : ".crt")),
                             "--uuid", (box == "A" ? m_boxA : m_boxB).toString(QUuid::WithoutBraces)};
    if (!extra.contains("--serial"))
        arguments << "--serial" << "ESSAI-" + box;
    if (!extra.contains("--namespace"))
        arguments << "--namespace" << m_namespace.toString(QUuid::WithoutBraces);
    for (int i = 0; i < extra.count(); i++)
        arguments << (i % 2 ? (extra.at(i).contains('.') ? path(extra.at(i)) : extra.at(i)) : extra.at(i));

    QString output;
    QCOMPARE(check(arguments, &output), exitCode);
    QVERIFY2(output.contains(message), qPrintable(output));
}

void BoxCertCheckTests::usageErrors()
{
    const QString uuid = m_boxA.toString(QUuid::WithoutBraces);
    const QString space = m_namespace.toString(QUuid::WithoutBraces);
    QString output;
    QCOMPARE(check({"--cert", path("boxA.crt"), "--ca", path("ca.crt"), "--uuid", uuid, "--namespace", space}, &output), 2);
    QCOMPARE(check({"--cert", path("boxA.crt"), "--ca", path("ca.crt"), "--uuid", uuid, "--serial", "ESSAI-A"}, &output), 2);
    QCOMPARE(check({"--cert", path("boxA.crt"), "--ca", path("ca.crt"), "--uuid", "not-a-uuid", "--serial", "ESSAI-A",
                    "--namespace", space}, &output), 2);
    QCOMPARE(check({"--cert", path("boxA.crt"), "--ca", path("ca.crt"), "--uuid", uuid, "--serial", "ESSAI-A",
                    "--namespace", "not-a-uuid"}, &output), 2);
    QCOMPARE(check({"--cert", path("boxA.crt"), "--ca", path("empty.crt"), "--uuid", uuid, "--serial", "ESSAI-A",
                    "--namespace", space}, &output), 2);
}

void BoxCertCheckTests::ruleIdenticalToRelay()
{
    // The tool must apply the rule of the relay: both carry the same boxidentity files. The relay
    // tests compare them too; this side sees a drift when only the relay changes.
    const QString relayDirectory = QString(SOURCE_DIR) + "/../etm-powersync-remote-proxy/libnymea-remoteproxy/tunnelproxy/";
    if (!QDir(relayDirectory).exists())
        QSKIP("etm-powersync-remote-proxy is not checked out next to this repository");

    for (const QString &name : {QString("boxidentity.h"), QString("boxidentity.cpp")}) {
        QFile relayCopy(relayDirectory + name);
        QFile toolCopy(QString(SOURCE_DIR) + "/tools/boxcert-check/" + name);
        QVERIFY(relayCopy.open(QIODevice::ReadOnly));
        QVERIFY(toolCopy.open(QIODevice::ReadOnly));
        QVERIFY2(relayCopy.readAll() == toolCopy.readAll(), qPrintable(name + " differs between the relay and etm-powersync-boxcert-check"));
    }
}

QTEST_MAIN(BoxCertCheckTests)
#include "boxcertchecktests.moc"

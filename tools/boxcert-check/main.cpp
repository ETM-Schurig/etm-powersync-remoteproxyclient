// SPDX-License-Identifier: LGPL-3.0-or-later
// Copyright (C) 2026, ETM-Schurig SARL
//
// etm-powersync-boxcert-check: says whether a box certificate will be accepted by the relay for
// this box, with the relay's own rule (boxidentity.cpp), plus the checks of the enrolment.

#include "boxidentity.h"

#include <QCommandLineParser>
#include <QCoreApplication>
#include <QFile>
#include <QFileInfo>
#include <QSslCertificate>
#include <QTextStream>

#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

namespace {

QList<QSslCertificate> readCertificates(const QString &fileName)
{
    QFile file(fileName);
    if (!file.open(QIODevice::ReadOnly))
        return QList<QSslCertificate>();
    return QSslCertificate::fromDevice(&file, QSsl::Pem);
}

bool readRevocationList(const QString &fileName, QSet<QByteArray> *fingerprints)
{
    QFile file(fileName);
    if (!file.open(QIODevice::ReadOnly))
        return false;
    while (!file.atEnd()) {
        QByteArray line = file.readLine();
        int comment = line.indexOf('#');
        if (comment >= 0)
            line.truncate(comment);
        line = line.trimmed().toLower().replace(":", "");
        if (!line.isEmpty())
            fingerprints->insert(line);
    }
    return true;
}

// Empty when the key is usable with the certificate, else the reason.
QString checkKey(const QString &keyFileName, const QString &certificateFileName)
{
    QFileInfo info(keyFileName);
    if (!info.exists())
        return "the key file does not exist";
    if (info.permissions() & (QFileDevice::ReadGroup | QFileDevice::WriteGroup | QFileDevice::ReadOther | QFileDevice::WriteOther))
        return "the key file is accessible to others than its owner (0600 expected)";

    QFile keyFile(keyFileName);
    QFile certificateFile(certificateFileName);
    if (!keyFile.open(QIODevice::ReadOnly) || !certificateFile.open(QIODevice::ReadOnly))
        return "cannot read the key or the certificate";
    const QByteArray keyData = keyFile.readAll();
    const QByteArray certificateData = certificateFile.readAll();

    BIO *keyBio = BIO_new_mem_buf(keyData.constData(), static_cast<int>(keyData.size()));
    EVP_PKEY *privateKey = PEM_read_bio_PrivateKey(keyBio, nullptr, nullptr, nullptr);
    BIO_free(keyBio);
    BIO *certificateBio = BIO_new_mem_buf(certificateData.constData(), static_cast<int>(certificateData.size()));
    X509 *certificate = PEM_read_bio_X509(certificateBio, nullptr, nullptr, nullptr);
    BIO_free(certificateBio);
    const bool matches = privateKey && certificate && X509_check_private_key(certificate, privateKey) == 1;
    X509_free(certificate);
    EVP_PKEY_free(privateKey);
    ERR_clear_error();
    return matches ? QString() : "the key does not belong to the certificate";
}

}

int main(int argc, char *argv[])
{
    QCoreApplication application(argc, argv);
    QCoreApplication::setApplicationName("etm-powersync-boxcert-check");

    QCommandLineParser parser;
    parser.setApplicationDescription("Checks that a box certificate will be accepted by the ETM-PowerSync relay for this box.\n"
                                     "Exit code: 0 accepted, 1 refused, 2 usage error.");
    parser.addHelpOption();
    QCommandLineOption certificateOption("cert", "Box certificate (PEM), e.g. box.crt.", "file");
    QCommandLineOption caOption("ca", "Box CA certificate(s) (PEM), e.g. ca.crt.", "file");
    QCommandLineOption uuidOption("uuid", "Expected box UUID (nymead [nymead] uuid).", "uuid");
    QCommandLineOption serialOption("serial", "Expected serial number (subject serialNumber).", "serial");
    QCommandLineOption namespaceOption("namespace", "ETM UUID namespace, as [BoxCertificates] uuidNamespace on the relay.", "uuid");
    QCommandLineOption keyOption("key", "Also check the private key: belongs to the certificate, mode 0600.", "file");
    QCommandLineOption revokedOption("revoked", "Revocation list of the relay (one SHA-256 fingerprint per line).", "file");
    parser.addOptions({certificateOption, caOption, uuidOption, serialOption, namespaceOption, keyOption, revokedOption});
    parser.process(application);

    QTextStream out(stdout);
    QTextStream err(stderr);
    if (!parser.isSet(certificateOption) || !parser.isSet(caOption) || !parser.isSet(uuidOption) || !parser.isSet(serialOption)
            || !parser.isSet(namespaceOption)) {
        err << "--cert, --ca, --uuid, --serial and --namespace are required (see --help)" << Qt::endl;
        return 2;
    }
    const QUuid uuid = QUuid::fromString(parser.value(uuidOption));
    if (uuid.isNull()) {
        err << "--uuid is not a UUID" << Qt::endl;
        return 2;
    }
    const QUuid uuidNamespace = QUuid::fromString(parser.value(namespaceOption));
    if (uuidNamespace.isNull()) {
        err << "--namespace is not a UUID" << Qt::endl;
        return 2;
    }
    const QList<QSslCertificate> caCertificates = readCertificates(parser.value(caOption));
    if (caCertificates.isEmpty()) {
        err << "no certificate in " << parser.value(caOption) << Qt::endl;
        return 2;
    }
    QSet<QByteArray> revoked;
    if (parser.isSet(revokedOption) && !readRevocationList(parser.value(revokedOption), &revoked)) {
        err << "cannot read " << parser.value(revokedOption) << Qt::endl;
        return 2;
    }

    auto refuse = [&out](const QString &reason) {
        out << "REFUSED: " << reason << Qt::endl;
        return 1;
    };

    const QList<QSslCertificate> chain = readCertificates(parser.value(certificateOption));
    QString detail;
    const boxidentity::Result result = boxidentity::verify(chain, caCertificates, revoked, uuid, uuidNamespace, &detail);
    if (result != boxidentity::Accepted)
        return refuse(boxidentity::resultToString(result) + (detail.isEmpty() ? QString() : " (" + detail + ")"));

    const QSslCertificate &leaf = chain.first();
    const QStringList serials = leaf.subjectInfo(QSslCertificate::SerialNumber);
    if (!serials.contains(parser.value(serialOption)))
        return refuse(QString("subject serialNumber is \"%1\", \"%2\" expected").arg(serials.join(","), parser.value(serialOption)));

    if (parser.isSet(keyOption)) {
        const QString keyProblem = checkKey(parser.value(keyOption), parser.value(certificateOption));
        if (!keyProblem.isEmpty())
            return refuse(keyProblem);
    }

    // Valid until the first expiry in the chain, the leaf or the box CA, as the relay counts it.
    QDateTime validUntil;
    boxidentity::signedByBoxCa(leaf, caCertificates, nullptr, &validUntil);
    out << "ACCEPTED: box " << uuid.toString(QUuid::WithoutBraces) << ", serial " << parser.value(serialOption)
        << ", valid until " << validUntil.toString(Qt::ISODate)
        << ", SHA-256 " << QString::fromLatin1(boxidentity::fingerprint(leaf)) << Qt::endl;
    return 0;
}

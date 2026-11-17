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

#include <QDateTime>
#include <QDir>
#include <QFile>
#include <QFileInfo>

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

namespace remoteproxyclient {

QString BoxCertificate::directory()
{
    const QByteArray environment = qgetenv("REMOTEPROXYCLIENT_CERTIFICATE_DIR");
    if (!environment.isEmpty())
        return QString::fromLocal8Bit(environment);
#ifdef BOX_CERTIFICATE_DIR
    return QStringLiteral(BOX_CERTIFICATE_DIR);
#else
    return QString();
#endif
}

BoxCertificate::Status BoxCertificate::load(const QString &directory, QSslCertificate *certificate, QSslKey *key, QString *detail)
{
    const QString certificateFileName = QDir(directory).filePath("box.crt");
    const QString keyFileName = QDir(directory).filePath("box.key");

    if (directory.isEmpty() || !QFileInfo::exists(certificateFileName) || !QFileInfo::exists(keyFileName)) {
        *detail = QString("no box.crt and box.key in \"%1\"").arg(directory);
        return Missing;
    }

    QFile certificateFile(certificateFileName);
    QFile keyFile(keyFileName);
    if (!certificateFile.open(QIODevice::ReadOnly) || !keyFile.open(QIODevice::ReadOnly)) {
        *detail = QString("cannot open box.crt or box.key in \"%1\"").arg(directory);
        return Unreadable;
    }
    const QByteArray certificateData = certificateFile.readAll();
    const QByteArray keyData = keyFile.readAll();

    const QList<QSslCertificate> certificates = QSslCertificate::fromData(certificateData, QSsl::Pem);
    if (certificates.isEmpty() || certificates.first().isNull()) {
        *detail = "box.crt is not a PEM certificate";
        return Unreadable;
    }

    // OpenSSL detects the key type (QSslKey needs it up front) and checks that the key belongs
    // to the certificate, which Qt cannot do.
    BIO *keyBio = BIO_new_mem_buf(keyData.constData(), static_cast<int>(keyData.size()));
    EVP_PKEY *privateKey = PEM_read_bio_PrivateKey(keyBio, nullptr, nullptr, nullptr);
    BIO_free(keyBio);
    if (!privateKey) {
        ERR_clear_error();
        *detail = "box.key is not a PEM private key";
        return Unreadable;
    }
    BIO *certificateBio = BIO_new_mem_buf(certificateData.constData(), static_cast<int>(certificateData.size()));
    X509 *x509 = PEM_read_bio_X509(certificateBio, nullptr, nullptr, nullptr);
    BIO_free(certificateBio);
    const bool matches = x509 && X509_check_private_key(x509, privateKey) == 1;
    const int keyType = EVP_PKEY_get_base_id(privateKey);
    X509_free(x509);
    EVP_PKEY_free(privateKey);
    ERR_clear_error();

    if (!matches) {
        *detail = "box.key does not belong to box.crt";
        return KeyMismatch;
    }

    QSsl::KeyAlgorithm algorithm;
    if (keyType == EVP_PKEY_EC) {
        algorithm = QSsl::Ec;
    } else if (keyType == EVP_PKEY_RSA) {
        algorithm = QSsl::Rsa;
    } else {
        *detail = "box.key is neither an EC nor an RSA key";
        return Unreadable;
    }
    const QSslKey sslKey(keyData, algorithm, QSsl::Pem, QSsl::PrivateKey);
    if (sslKey.isNull()) {
        *detail = "box.key cannot be loaded";
        return Unreadable;
    }

    const QSslCertificate &leaf = certificates.first();
    const QDateTime now = QDateTime::currentDateTimeUtc();
    if (now < leaf.effectiveDate() || now > leaf.expiryDate()) {
        *detail = QString("box.crt is valid from %1 to %2").arg(leaf.effectiveDate().toString(Qt::ISODate), leaf.expiryDate().toString(Qt::ISODate));
        return Expired;
    }

    *certificate = leaf;
    *key = sslKey;
    *detail = QString("subject \"%1\", SHA-256 %2").arg(leaf.subjectDisplayName(), QString::fromLatin1(leaf.digest(QCryptographicHash::Sha256).toHex()));
    return Valid;
}

QString BoxCertificate::statusToString(Status status)
{
    switch (status) {
    case Valid:
        return "valid";
    case Missing:
        return "missing";
    case Unreadable:
        return "unreadable";
    case KeyMismatch:
        return "key does not match";
    case Expired:
        return "expired";
    }
    return "unknown";
}

}

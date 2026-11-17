// SPDX-License-Identifier: LGPL-3.0-or-later
// Copyright (C) 2026, ETM-Schurig SARL
//
// Rule that ties a box certificate to a box. The SAME file is used by the relay
// (etm-powersync-remote-proxy, libnymea-remoteproxy/tunnelproxy/) and by
// etm-powersync-boxcert-check (etm-powersync-remoteproxyclient, tools/boxcert-check/).
// Change it in both places at once: a test of the relay compares the two copies.

#ifndef BOXIDENTITY_H
#define BOXIDENTITY_H

#include <QByteArray>
#include <QDateTime>
#include <QList>
#include <QSet>
#include <QSslCertificate>
#include <QString>
#include <QUuid>

namespace boxidentity {

enum Result {
    Accepted,
    NoCertificate,
    Untrusted,
    Revoked,
    WrongIdentity,
    WrongProfile
};

// The leaf (first certificate, the others are ignored) must have the box profile (profileMatches),
// be signed by one of the box CA certificates (the intermediate CA, partial chain allowed), for
// client authentication, validity dates included. It must not be self-signed or itself one of the
// CA certificates. It must not be revoked (SHA-256 fingerprints in lowercase hex) and must be
// issued for the UUID (identityMatches). detail, if given, says why the profile or the identity
// does not match, or why the chain is refused.
Result verify(const QList<QSslCertificate> &chain, const QList<QSslCertificate> &caCertificates,
              const QSet<QByteArray> &revokedFingerprints, const QUuid &uuid, const QUuid &uuidNamespace,
              QString *detail = nullptr);

// The profile part of verify(), required: basicConstraints present, critical and CA:FALSE, without
// pathLenConstraint; keyUsage present with digitalSignature; extendedKeyUsage present with clientAuth. Other bits
// and other extensions are not looked at.
bool profileMatches(const QSslCertificate &leaf, QString *detail = nullptr);

// The chain part of verify(): the leaf alone is signed by one of the CA certificates. detail, if
// given, says why not: expired, not yet valid, wrong usage, or the OpenSSL error in words.
// validUntil, if given, is the first expiry in the verified chain (leaf or box CA).
bool signedByBoxCa(const QSslCertificate &leaf, const QList<QSslCertificate> &caCertificates,
                   QString *detail = nullptr, QDateTime *validUntil = nullptr);

// The identity rule, all of it:
// - exactly one SAN URI urn:uuid:<UUID>: the prefix urn:uuid: in any case, then exactly 36
//   characters 8-4-4-4-12 in hexadecimal (any case), nothing else; a malformed one still counts;
//   and that UUID is the UUID;
// - the CN plays no part;
// - exactly one non-empty serialNumber (OID 2.5.4.5) in the subject, and
//   UUIDv5(uuidNamespace, UTF-8 bytes of the serialNumber) is the UUID.
// uuidNamespace is the public ETM namespace ([BoxCertificates] uuidNamespace on the relay).
bool identityMatches(const QSslCertificate &certificate, const QUuid &uuid, const QUuid &uuidNamespace,
                     QString *detail = nullptr);

// Lowercase hex SHA-256 of the DER certificate, as in the revocation list.
QByteArray fingerprint(const QSslCertificate &certificate);

QString resultToString(Result result);

}

#endif // BOXIDENTITY_H

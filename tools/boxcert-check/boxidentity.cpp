// SPDX-License-Identifier: LGPL-3.0-or-later
// Copyright (C) 2026, ETM-Schurig SARL
//
// Rule that ties a box certificate to a box: see boxidentity.h.

#include "boxidentity.h"

#include <QCryptographicHash>
#include <QRegularExpression>

#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/x509_vfy.h>

namespace boxidentity {

namespace {

X509 *toX509(const QSslCertificate &certificate)
{
    QByteArray der = certificate.toDer();
    const unsigned char *data = reinterpret_cast<const unsigned char *>(der.constData());
    return d2i_X509(nullptr, &data, static_cast<long>(der.size()));
}

}

Result verify(const QList<QSslCertificate> &chain, const QList<QSslCertificate> &caCertificates,
              const QSet<QByteArray> &revokedFingerprints, const QUuid &uuid, const QUuid &uuidNamespace,
              QString *detail)
{
    if (chain.isEmpty() || chain.first().isNull())
        return NoCertificate;

    const QSslCertificate &leaf = chain.first();
    if (!profileMatches(leaf, detail))
        return WrongProfile;

    if (!signedByBoxCa(leaf, caCertificates, detail))
        return Untrusted;

    if (revokedFingerprints.contains(fingerprint(leaf)))
        return Revoked;

    if (!identityMatches(leaf, uuid, uuidNamespace, detail))
        return WrongIdentity;

    return Accepted;
}

bool profileMatches(const QSslCertificate &leaf, QString *detail)
{
    QString problem;
    X509 *x509 = toX509(leaf);
    const uint32_t flags = x509 ? X509_get_extension_flags(x509) : 0;
    const int basicConstraints = x509 ? X509_get_ext_by_NID(x509, NID_basic_constraints, -1) : -1;
    BASIC_CONSTRAINTS *constraints = x509 ? static_cast<BASIC_CONSTRAINTS *>(X509_get_ext_d2i(x509, NID_basic_constraints, nullptr, nullptr)) : nullptr;
    if (!x509) {
        problem = "unreadable certificate";
    } else if (flags & EXFLAG_CA) {
        // X509_check_ca() alone lets CA:TRUE through when keyUsage lacks keyCertSign.
        problem = "basicConstraints CA:TRUE, a box certificate is never a CA";
    } else if (basicConstraints < 0 || !X509_EXTENSION_get_critical(X509_get_ext(x509, basicConstraints))) {
        problem = "no critical basicConstraints CA:FALSE";
    } else if (!constraints || constraints->pathlen) {
        // RFC 5280: pathLenConstraint only with CA:TRUE. OpenSSL does not refuse it on a leaf.
        problem = "basicConstraints with a pathLenConstraint, a box certificate is never a CA";
    } else if (!(flags & EXFLAG_KUSAGE) || !(X509_get_key_usage(x509) & KU_DIGITAL_SIGNATURE)) {
        problem = "no keyUsage digitalSignature";
    } else if (!(flags & EXFLAG_XKUSAGE) || !(X509_get_extended_key_usage(x509) & XKU_SSL_CLIENT)) {
        problem = "no extendedKeyUsage clientAuth";
    }
    BASIC_CONSTRAINTS_free(constraints);
    X509_free(x509);

    if (detail)
        *detail = problem;
    return problem.isEmpty();
}

bool signedByBoxCa(const QSslCertificate &leaf, const QList<QSslCertificate> &caCertificates, QString *detail,
                   QDateTime *validUntil)
{
    if (detail)
        detail->clear();
    if (validUntil)
        *validUntil = QDateTime();
    if (leaf.isNull())
        return false;

    // Chain to the ETM box CA with OpenSSL: Qt only verifies against the system store, and never
    // with a partial chain. box-ca.pem holds the box intermediate CA only, the root stays offline:
    // the chain may stop at the intermediate. The box sends its leaf only; anything else it sends
    // is ignored, so a leaf of another intermediate of the same root never chains to a root that
    // would have been put in box-ca.pem by mistake.
    X509_STORE *store = X509_STORE_new();
    X509_STORE_set_flags(store, X509_V_FLAG_PARTIAL_CHAIN);
    foreach (const QSslCertificate &caCertificate, caCertificates) {
        X509 *ca = toX509(caCertificate);
        if (ca) {
            X509_STORE_add_cert(store, ca);
            X509_free(ca);
        }
    }
    X509 *leafX509 = toX509(leaf);
    X509_STORE_CTX *context = X509_STORE_CTX_new();
    QString problem;
    if (!leafX509 || !context) {
        problem = "unreadable certificate";
    } else if (X509_get_extension_flags(leafX509) & EXFLAG_SS) {
        problem = "self-signed";
    } else if (X509_check_ca(leafX509) != 0) {
        // A CA is never a box.
        problem = "a CA";
    } else if (X509_STORE_CTX_init(context, store, leafX509, nullptr) != 1
               || X509_STORE_CTX_set_purpose(context, X509_PURPOSE_SSL_CLIENT) != 1) {
        problem = "cannot verify";
    } else if (X509_verify_cert(context) != 1) {
        // The OpenSSL error, in words: the result stays a refusal, only the reason differs.
        const int error = X509_STORE_CTX_get_error(context);
        const QString which = X509_STORE_CTX_get_error_depth(context) == 0 ? "certificate" : "box CA";
        if (error == X509_V_ERR_CERT_HAS_EXPIRED)
            problem = which + " expired";
        else if (error == X509_V_ERR_CERT_NOT_YET_VALID)
            problem = which + " not yet valid";
        else if (error == X509_V_ERR_INVALID_PURPOSE)
            problem = "wrong usage for a TLS client";
        else
            problem = QString("not signed by the box CA (%1)").arg(X509_verify_cert_error_string(error));
    } else if (sk_X509_num(X509_STORE_CTX_get0_chain(context)) < 2) {
        // With a partial chain, a leaf put in box-ca.pem would trust itself: a CA must sign it.
        problem = "the certificate itself is in box-ca.pem";
    }
    const bool trusted = problem.isEmpty();
    if (detail)
        *detail = problem;
    // The chain is valid until the first of its certificates expires: the leaf, or the box CA.
    STACK_OF(X509) *verified = trusted ? X509_STORE_CTX_get0_chain(context) : nullptr;
    for (int i = 0; validUntil && verified && i < sk_X509_num(verified); i++) {
        unsigned char *der = nullptr;
        const int length = i2d_X509(sk_X509_value(verified, i), &der);
        const QDateTime expiry = length > 0 ? QSslCertificate(QByteArray(reinterpret_cast<const char *>(der), length), QSsl::Der).expiryDate()
                                            : QDateTime();
        OPENSSL_free(der);
        if (expiry.isValid() && (!validUntil->isValid() || expiry < *validUntil))
            *validUntil = expiry;
    }
    X509_STORE_CTX_free(context);
    X509_free(leafX509);
    X509_STORE_free(store);
    ERR_clear_error();
    return trusted;
}

bool identityMatches(const QSslCertificate &certificate, const QUuid &uuid, const QUuid &uuidNamespace, QString *detail)
{
    QString problem;
    X509 *x509 = toX509(certificate);

    // Exactly one SAN URI urn:uuid:, equal to the UUID. Qt does not expose URI subject alternative
    // names: read them with OpenSSL. The CN plays no part in the identity. The text is compared
    // exactly: the prefix in any case, then 36 characters 8-4-4-4-12 in hexadecimal (any case,
    // RFC 4122), nothing before, nothing after, no braces. A malformed urn:uuid still counts as
    // one, so that "exactly one" holds; QUuid::fromString() alone would accept braces and trailing
    // characters. Anchored on the whole text: "$" would let a final line feed through.
    static const QRegularExpression uuidText(QRegularExpression::anchoredPattern(
        "[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"));
    const QByteArray urn = "urn:uuid:";
    QList<QUuid> sanUuids;
    GENERAL_NAMES *names = x509 ? static_cast<GENERAL_NAMES *>(X509_get_ext_d2i(x509, NID_subject_alt_name, nullptr, nullptr)) : nullptr;
    for (int i = 0; names && i < sk_GENERAL_NAME_num(names); i++) {
        const GENERAL_NAME *name = sk_GENERAL_NAME_value(names, i);
        if (name->type != GEN_URI)
            continue;
        QByteArray uri(reinterpret_cast<const char *>(ASN1_STRING_get0_data(name->d.uniformResourceIdentifier)),
                       ASN1_STRING_length(name->d.uniformResourceIdentifier));
        if (uri.left(urn.size()).toLower() != urn)
            continue;
        const QString text = QString::fromLatin1(uri.mid(urn.size()));
        sanUuids.append(uuidText.match(text).hasMatch() ? QUuid::fromString(text) : QUuid());
    }
    GENERAL_NAMES_free(names);

    // Exactly one non-empty serialNumber (OID 2.5.4.5) in the subject, as UTF-8.
    QList<QByteArray> serialNumbers;
    X509_NAME *subject = x509 ? X509_get_subject_name(x509) : nullptr;
    for (int i = subject ? X509_NAME_get_index_by_NID(subject, NID_serialNumber, -1) : -1; i >= 0;
         i = X509_NAME_get_index_by_NID(subject, NID_serialNumber, i)) {
        unsigned char *utf8 = nullptr;
        int length = ASN1_STRING_to_UTF8(&utf8, X509_NAME_ENTRY_get_data(X509_NAME_get_entry(subject, i)));
        serialNumbers.append(length >= 0 ? QByteArray(reinterpret_cast<const char *>(utf8), length) : QByteArray());
        OPENSSL_free(utf8);
    }
    X509_free(x509);

    if (uuid.isNull()) {
        problem = "no UUID";
    } else if (uuidNamespace.isNull()) {
        problem = "no ETM UUID namespace configured";
    } else if (sanUuids.count() != 1) {
        problem = QString("%1 SAN urn:uuid, exactly one expected").arg(sanUuids.count());
    } else if (sanUuids.first().isNull()) {
        problem = "SAN urn:uuid is not a UUID (36 characters 8-4-4-4-12, no braces)";
    } else if (sanUuids.first() != uuid) {
        problem = "SAN urn:uuid is another UUID";
    } else if (serialNumbers.count() != 1 || serialNumbers.first().isEmpty()) {
        problem = "exactly one non-empty serialNumber expected in the subject";
    } else if (QUuid::createUuidV5(uuidNamespace, serialNumbers.first()) != uuid) {
        problem = "the UUID is not UUIDv5(ETM namespace, serialNumber)";
    }

    if (detail)
        *detail = problem;
    return problem.isEmpty();
}

QByteArray fingerprint(const QSslCertificate &certificate)
{
    return certificate.digest(QCryptographicHash::Sha256).toHex();
}

QString resultToString(Result result)
{
    switch (result) {
    case Accepted:
        return "accepted";
    case NoCertificate:
        return "no certificate";
    case Untrusted:
        return "not signed by the box CA";
    case Revoked:
        return "revoked";
    case WrongIdentity:
        return "issued for another box";
    case WrongProfile:
        return "not a box certificate";
    }
    return "unknown";
}

}

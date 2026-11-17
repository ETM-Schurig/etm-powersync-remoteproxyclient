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

#ifndef BOXCERTIFICATE_H
#define BOXCERTIFICATE_H

#include <QSslCertificate>
#include <QSslKey>
#include <QString>

namespace remoteproxyclient {

// Internal (not installed): the client certificate a box presents to the relay on TCP.
class BoxCertificate
{
public:
    enum Status {
        Valid,
        Missing,
        Unreadable,
        KeyMismatch,
        Expired
    };

    // Directory of box.crt and box.key: the environment variable
    // REMOTEPROXYCLIENT_CERTIFICATE_DIR, else the build option BOX_CERTIFICATE_DIR. Empty when
    // neither is set: the library then behaves exactly as upstream.
    static QString directory();

    // Reads the files on every call. Never logs their content.
    static Status load(const QString &directory, QSslCertificate *certificate, QSslKey *key, QString *detail);

    static QString statusToString(Status status);
};

}

#endif // BOXCERTIFICATE_H

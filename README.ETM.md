# etm-powersync-remoteproxyclient

Client library of the ETM-PowerSync remote access relay, loaded by nymead on the boxes. ETM fork of
`libnymea-remoteproxyclient`, based on the upstream tag **1.15.2** of `nymea-remoteproxy` (the version
running on the fleet). The relay itself lives in another repository; the server, the monitor, the
tunnelclient and their tests are removed from here.

## Package

`etm-powersync-remoteproxyclient`, version `1.15.2+etmN`, renamed package (path B):

- `Provides: libnymea-remoteproxyclient (= ${binary:Version})`. `libnymea-core` 1.15.2 depends on
  `libnymea-remoteproxyclient (>= 1.15.2+202606191336~trixie1)`: a `Provides` of `= 1.15.2` would
  not satisfy it, `1.15.2+etmN` does.
- `Conflicts` and `Replaces: libnymea-remoteproxyclient`: same file
  `libnymea-remoteproxyclient.so.1`, same public ABI.
- No `-dev` package: nymead is not rebuilt against this library.

When nymea moves to 1.15.3 or later, `libnymea-core` will require a version this package does not
provide: a `1.15.3+etm1` will be needed, or a return to the upstream library.

## Box certificate

The library reads `box.crt` and `box.key` on each TLS connection to the relay, from the directory
given by the environment variable `REMOTEPROXYCLIENT_CERTIFICATE_DIR`, otherwise by the build option
`BOX_CERTIFICATE_DIR` (the package sets it to `/etc/etm-powersync/remote-proxy`). If it is missing,
unreadable, its key does not match or it is out of validity: connection without a certificate, as
upstream, with a warning. No hot reload: a new certificate is used on the next connection
(restart nymead after enrolment).

Profile of the box certificate (signed by the boxes' intermediate CA):

| Field | Value |
|---|---|
| Key | ECDSA P-256, generated on the box |
| Subject | `CN=<nymead UUID>`, `serialNumber=<serial number>` (OID 2.5.4.5) |
| SAN | `URI:urn:uuid:<nymead UUID>` |
| `basicConstraints` | critical, `CA:FALSE`, no `pathlen` |
| `keyUsage` | critical, `digitalSignature` |
| `extendedKeyUsage` | `clientAuth` |
| Signature | `ecdsa-with-SHA256` |
| Validity | 10 years, not beyond that of the intermediate CA |

The relay accepts the box if the certificate has this profile (`basicConstraints`, `keyUsage` and
`extendedKeyUsage` required), if it is signed by the boxes' intermediate CA for `clientAuth` (the
chain stops at the intermediate, the root stays offline), if it is not revoked, and if it carries
exactly one `urn:uuid:` SAN equal to the announced UUID. The CN does not count. The subject carries
exactly one `serialNumber`, and UUID = UUIDv5(ETM namespace, serial number). The serial number
remains an identifier, not a proof: only the enrolment verifies it.

## Tool `etm-powersync-boxcert-check`

Separate package. Applies the relay's rule (`tools/boxcert-check/boxidentity.cpp`, a file identical
byte for byte on the relay side: a test in each repository compares the two copies), then the
expected serial number, and the key if `--key` is given (same pair, mode 0600). `--namespace` is
the ETM namespace, the relay's `[BoxCertificates] uuidNamespace`.

```sh
etm-powersync-boxcert-check --cert box.crt --ca ca.crt --uuid <UUID> --serial <number> --namespace <UUID> [--key box.key] [--revoked list]
```

Exit code: 0 accepted, 1 refused (with the reason), 2 usage error.

## License

LGPL-3.0-or-later, as upstream: headers and license files are kept. The package is installed
on customers' boxes; the modified sources are provided under the same license.

## Build

```sh
mkdir -p /tmp/build && cd /tmp/build
qmake6 <repository>/nymea-remoteproxy.pro && make -j4
```

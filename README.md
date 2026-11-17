# etm-powersync-remoteproxyclient

Client library of the ETM PowerSync remote access relay, loaded by nymead on ETM PowerSync boxes.

It is a fork of `libnymea-remoteproxyclient` from the upstream
[nymea-remoteproxy](https://github.com/nymea/nymea-remoteproxy) tag **1.15.2** (the nymea version
of the boxes). Only the client library is kept here: the relay server, the monitor, the tunnel
client and their tests are not part of this repository.

Remote access is **disabled by default** on an ETM PowerSync box. It is only used once the
customer turns it on in the ETM PowerSync app; without it, the box is reachable on the local
network only.

## What it adds to upstream

- **Box certificate.** At each TLS connection to the relay, the library presents the box
  certificate (`box.crt`, `box.key`) found in `/etc/etm-powersync/remote-proxy` (or in the
  directory given by `REMOTEPROXYCLIENT_CERTIFICATE_DIR`). Without a valid certificate it connects
  as upstream does, with a warning.
- **`etm-powersync-boxcert-check`**, a small tool that says whether a box certificate will be
  accepted by the relay for a given box UUID and serial number.

The public ABI is unchanged.

## Packages

| Package | Content |
|---|---|
| `etm-powersync-remoteproxyclient` (`1.15.2+etmN`) | the library; `Provides`, `Conflicts` and `Replaces` `libnymea-remoteproxyclient` (same file, same ABI) |
| `etm-powersync-boxcert-check` | the certificate check tool |

They are published in the ETM PowerSync APT repository (see the
[documentation](https://docs.etm-powersync.fr/installation/depot-apt/)); `powersync-core` pulls
in the library.

## Build

```sh
sudo apt install debhelper dpkg-dev libssl-dev pkg-config qt6-base-dev qt6-base-dev-tools qt6-websockets-dev
mkdir -p /tmp/build && cd /tmp/build
qmake6 <repository>/nymea-remoteproxy.pro && make -j4
```

Debian packages: `dpkg-buildpackage -b -us -uc` from the repository root.

## More

Certificate profile, packaging details and the check tool, in French: [README.ETM.md](README.ETM.md).

## License

LGPL-3.0-or-later, as upstream (`COPYING.LESSER`, `LICENSE.LGPL3`). The library is installed on
customer boxes; the modified sources are provided under the same license here.

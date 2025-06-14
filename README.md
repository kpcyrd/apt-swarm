# apt-swarm

An attempt to make a secure public p2p protocol that gossips about signed
`InRelease` files to implement an update transparency log.

![Screenshot of a keyring along with the number of known signatures](.github/keyring-screenshot.png)

## Running a node

<a href="https://repology.org/project/apt-swarm/versions"><img align="right" src="https://repology.org/badge/vertical-allrepos/apt-swarm.svg" alt="Packaging status"></a>

Install dependencies (Arch Linux):

```
pacman -S podman
```

Install dependencies (Debian/Ubuntu):

```
apt-get install podman catatonit
```

Create a systemd service at `/etc/systemd/system/apt-swarm.service`:

```
cat > /etc/systemd/system/apt-swarm.service <<EOF
[Unit]
Description=apt-swarm p2p container
Documentation=https://github.com/kpcyrd/apt-swarm

[Service]
ExecStartPre=-/usr/bin/mkdir -p /opt/apt-swarm
ExecStart=/usr/bin/podman run --rm --pull always --init \
    -v /opt/apt-swarm:/data \
    -p 16169:16169 \
    ghcr.io/kpcyrd/apt-swarm:edge p2p \
    --check-container-updates ghcr.io/kpcyrd/apt-swarm:edge
Restart=always
RestartSec=10

[Install]
WantedBy=default.target
EOF
```

Start the service:

```
systemctl daemon-reload
systemctl enable --now apt-swarm
```

Watch logs:

```
journalctl -fu apt-swarm
```

## Running a node (kubernetes)

```
minikube start
kubectl create ns apt-swarm 2>/dev/null || true
kubectl apply -f contrib/k8s.yaml -n apt-swarm
```

## Configuring a repository to monitor

To ascii armor the pgp key use this command:

```
sq packet armor < contrib/signal-desktop-keyring.pgp
```

Then write a configuration like this:

```toml
[[repository]]
urls = ["https://updates.signal.org/desktop/apt/dists/xenial/InRelease"]
keyring = """
-----BEGIN PGP PUBLIC KEY BLOCK-----

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
N+O606NOXLwcmq5KZL0g
=zyVo
-----END PGP PUBLIC KEY BLOCK-----
"""
```

## Status

This project is experimental. PGP is complicated and p2p security is difficult,
running this program may use up a lot of disk space on your computer if
somebody finds a way to bypass the vandalism protection.

There's also the risk of a false-negative, the pgp implementation used by
apt-get may consider a signature as valid that we consider invalid. If
apt-swarm considers the signature as invalid it won't accept this release into
the network and it won't appear in your audit logs.

apt-swarm can't detect network-partitioning attacks and doesn't intend to.

[![Star History Chart](https://api.star-history.com/svg?repos=kpcyrd/apt-swarm&type=Date)](https://www.star-history.com/#kpcyrd/apt-swarm&Date)

## Trivia

As part of this project, a [bug causing the pgp parser to
crash](https://gitlab.com/sequoia-pgp/sequoia/-/issues/1005) was identified in
Sequoia OpenPGP in 2023 through fuzzing.

A bug that could in some cases lead to [silent data
loss](https://github.com/tokio-rs/tokio/issues/7174) was identified in Tokio in
2025.

## Funding

[![](.github/lolgpt.png)](https://github.com/sponsors/kpcyrd)

## License

`GPL-3.0-or-later`

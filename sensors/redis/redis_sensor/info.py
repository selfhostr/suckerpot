"""``INFO`` output in the layout of Redis 7.2, generated from the deployment profile."""

from __future__ import annotations

import time
from dataclasses import dataclass, field

from redis_sensor.identity import Profile

DEFAULT_SECTIONS = (
    "server",
    "clients",
    "memory",
    "persistence",
    "stats",
    "replication",
    "cpu",
    "modules",
    "errorstats",
    "cluster",
    "keyspace",
)
ALL_SECTIONS = (*DEFAULT_SECTIONS[:-1], "commandstats", "latencystats", "keyspace")
_ALIASES = {"all": ALL_SECTIONS, "everything": ALL_SECTIONS, "default": DEFAULT_SECTIONS}


@dataclass
class ServerContext:
    """Process-wide facts that INFO reports; the sensor keeps the counters up to date."""

    profile: Profile
    port: int = 6379
    started: float = field(default_factory=time.monotonic)
    started_wall: float = field(default_factory=time.time)
    clients: int = 1
    total_connections: int = 0
    total_commands: int = 0
    net_in: int = 0
    net_out: int = 0
    rejected: int = 0

    def uptime(self) -> int:
        return self.profile.uptime_offset + int(time.monotonic() - self.started)


@dataclass
class InfoView:
    """What a single connection sees besides the process-wide facts."""

    client_id: int
    keys: int
    dirty: int
    last_save: int | None
    role_master: tuple[str, int] | None
    appendonly: bool
    maxmemory: int
    requirepass: bool
    expires: int = 0
    avg_ttl_ms: int = 0


def _human(n: int) -> str:
    if n < 1024:
        return f"{n}B"
    for unit, size in (("K", 1 << 10), ("M", 1 << 20), ("G", 1 << 30)):
        if n < size * 1024 or unit == "G":
            return f"{n / size:.2f}{unit}"
    return f"{n}B"  # pragma: no cover


def parse_sections(args: list[str]) -> list[str]:
    """Section names for ``INFO [section ...]``; unknown names yield nothing, as in Redis."""
    if not args:
        return list(DEFAULT_SECTIONS)
    out: list[str] = []
    for raw in args[:16]:
        name = raw.lower()
        for item in _ALIASES.get(name, (name,)):
            if item not in out:
                out.append(item)
    return out


def render_info(ctx: ServerContext, view: InfoView, sections: list[str]) -> str:
    p = ctx.profile
    up = ctx.uptime()
    now = time.time()
    out: list[str] = []

    def section(title: str, lines: list[str]) -> None:
        if out:
            out.append("")
        out.append(f"# {title}")
        out.extend(lines)

    used = p.base_memory + view.keys * 120 + ctx.total_commands % 4096
    rss = used + p.rss_extra
    peak = max(used, p.base_memory + 60_000)
    save_time = int(now - p.saved_ago - (up % 3600)) if view.last_save is None else view.last_save
    for name in sections:
        if name == "server":
            section(
                "Server",
                [
                    f"redis_version:{p.version}",
                    f"redis_git_sha1:{p.git_sha1}",
                    "redis_git_dirty:0",
                    f"redis_build_id:{p.build_id}",
                    "redis_mode:standalone",
                    f"os:Linux {p.kernel} x86_64",
                    "arch_bits:64",
                    "monotonic_clock:POSIX clock_gettime",
                    "multiplexing_api:epoll",
                    "atomicvar_api:c11-builtin",
                    f"gcc_version:{p.gcc_version}",
                    f"process_id:{p.process_id}",
                    f"process_supervised:{p.supervised}",
                    f"run_id:{p.run_id}",
                    f"tcp_port:{ctx.port}",
                    f"server_time_usec:{int(now * 1_000_000)}",
                    f"uptime_in_seconds:{up}",
                    f"uptime_in_days:{up // 86400}",
                    "hz:10",
                    "configured_hz:10",
                    f"lru_clock:{int(now) % 16777216}",
                    f"executable:{p.executable}",
                    f"config_file:{p.config_file}",
                    "io_threads_active:0",
                ],
            )
        elif name == "clients":
            section(
                "Clients",
                [
                    f"connected_clients:{max(1, ctx.clients)}",
                    "cluster_connections:0",
                    "maxclients:10000",
                    "client_recent_max_input_buffer:20480",
                    "client_recent_max_output_buffer:0",
                    "blocked_clients:0",
                    "tracking_clients:0",
                    "clients_in_timeout_table:0",
                ],
            )
        elif name == "memory":
            section(
                "Memory",
                [
                    f"used_memory:{used}",
                    f"used_memory_human:{_human(used)}",
                    f"used_memory_rss:{rss}",
                    f"used_memory_rss_human:{_human(rss)}",
                    f"used_memory_peak:{peak}",
                    f"used_memory_peak_human:{_human(peak)}",
                    f"used_memory_peak_perc:{used * 100 / peak:.2f}%",
                    f"used_memory_overhead:{p.base_memory - 40_000}",
                    "used_memory_startup:865752",
                    f"used_memory_dataset:{max(0, used - p.base_memory + 40_000)}",
                    "used_memory_dataset_perc:30.00%",
                    "allocator_allocated:1330608",
                    "allocator_active:1646592",
                    "allocator_resident:5230592",
                    "total_system_memory:8341512192",
                    "total_system_memory_human:7.77G",
                    "used_memory_lua:31744",
                    "used_memory_vm_eval:31744",
                    "used_memory_lua_human:31.00K",
                    "used_memory_scripts_eval:0",
                    "number_of_cached_scripts:0",
                    "number_of_functions:0",
                    "number_of_libraries:0",
                    "used_memory_vm_functions:32768",
                    "used_memory_vm_total:64512",
                    "used_memory_vm_total_human:63.00K",
                    "used_memory_functions:184",
                    "used_memory_scripts:184",
                    "used_memory_scripts_human:184B",
                    f"maxmemory:{view.maxmemory}",
                    f"maxmemory_human:{_human(view.maxmemory)}",
                    "maxmemory_policy:noeviction",
                    "allocator_frag_ratio:1.24",
                    "allocator_frag_bytes:316000",
                    "allocator_rss_ratio:3.18",
                    "allocator_rss_bytes:3584000",
                    "rss_overhead_ratio:1.35",
                    "rss_overhead_bytes:1900544",
                    f"mem_fragmentation_ratio:{rss / used:.2f}",
                    f"mem_fragmentation_bytes:{rss - used}",
                    "mem_not_counted_for_evict:0",
                    "mem_replication_backlog:0",
                    "mem_total_replication_buffers:0",
                    "mem_clients_slaves:0",
                    "mem_clients_normal:1800",
                    "mem_cluster_links:0",
                    "mem_aof_buffer:0",
                    "mem_allocator:jemalloc-5.3.0",
                    "active_defrag_running:0",
                    "lazyfree_pending_objects:0",
                    "lazyfreed_objects:0",
                ],
            )
        elif name == "persistence":
            section(
                "Persistence",
                [
                    "loading:0",
                    "async_loading:0",
                    "current_cow_peak:0",
                    "current_cow_size:0",
                    "current_cow_size_age:0",
                    "current_fork_perc:0.00",
                    "current_save_keys_processed:0",
                    "current_save_keys_total:0",
                    f"rdb_changes_since_last_save:{view.dirty}",
                    "rdb_bgsave_in_progress:0",
                    f"rdb_last_save_time:{save_time}",
                    "rdb_last_bgsave_status:ok",
                    "rdb_last_bgsave_time_sec:0",
                    "rdb_current_bgsave_time_sec:-1",
                    "rdb_saves:7",
                    "rdb_last_cow_size:446464",
                    "rdb_last_load_keys_expired:0",
                    "rdb_last_load_keys_loaded:0",
                    f"aof_enabled:{int(view.appendonly)}",
                    "aof_rewrite_in_progress:0",
                    "aof_rewrite_scheduled:0",
                    "aof_last_rewrite_time_sec:-1",
                    "aof_current_rewrite_time_sec:-1",
                    "aof_last_bgrewrite_status:ok",
                    "aof_rewrites:0",
                    "aof_rewrites_consecutive_failures:0",
                    "aof_last_write_status:ok",
                    "aof_last_cow_size:0",
                    "module_fork_in_progress:0",
                    "module_fork_last_cow_size:0",
                ],
            )
        elif name == "stats":
            ops = ctx.total_commands * 4 + up // 2
            section(
                "Stats",
                [
                    f"total_connections_received:{ctx.total_connections + up // 90}",
                    f"total_commands_processed:{ops}",
                    "instantaneous_ops_per_sec:0",
                    f"total_net_input_bytes:{ctx.net_in + ops * 38}",
                    f"total_net_output_bytes:{ctx.net_out + ops * 52}",
                    "total_net_repl_input_bytes:0",
                    "total_net_repl_output_bytes:0",
                    "instantaneous_input_kbps:0.00",
                    "instantaneous_output_kbps:0.00",
                    "instantaneous_input_repl_kbps:0.00",
                    "instantaneous_output_repl_kbps:0.00",
                    f"rejected_connections:{ctx.rejected}",
                    "sync_full:0",
                    "sync_partial_ok:0",
                    "sync_partial_err:0",
                    "expired_keys:0",
                    "expired_stale_perc:0.00",
                    "expired_time_cap_reached_count:0",
                    "expire_cycle_cpu_milliseconds:%d" % (up // 3),
                    "evicted_keys:0",
                    "evicted_clients:0",
                    "total_eviction_exceeded_time:0",
                    "current_eviction_exceeded_time:0",
                    f"keyspace_hits:{ops // 3}",
                    f"keyspace_misses:{ops // 11}",
                    "pubsub_channels:0",
                    "pubsub_patterns:0",
                    "pubsubshard_channels:0",
                    "latest_fork_usec:312",
                    "total_forks:7",
                    "migrate_cached_sockets:0",
                    "slave_expires_tracked_keys:0",
                    "active_defrag_hits:0",
                    "active_defrag_misses:0",
                    "active_defrag_key_hits:0",
                    "active_defrag_key_misses:0",
                    "total_active_defrag_time:0",
                    "current_active_defrag_time:0",
                    "tracking_total_keys:0",
                    "tracking_total_items:0",
                    "tracking_total_prefixes:0",
                    "unexpected_error_replies:0",
                    "total_error_replies:%d" % (ops // 700),
                    "dump_payload_sanitizations:0",
                    f"total_reads_processed:{ops + ctx.total_connections}",
                    f"total_writes_processed:{ops}",
                    "io_threaded_reads_processed:0",
                    "io_threaded_writes_processed:0",
                    "reply_buffer_shrinks:%d" % (up // 5000),
                    "reply_buffer_expands:%d" % (up // 9000),
                ],
            )
        elif name == "replication":
            if view.role_master is None:
                lines = [
                    "role:master",
                    "connected_slaves:0",
                    "master_failover_state:no-failover",
                    f"master_replid:{p.replid}",
                    "master_replid2:" + "0" * 40,
                    "master_repl_offset:0",
                    "second_repl_offset:-1",
                    "repl_backlog_active:0",
                    "repl_backlog_size:1048576",
                    "repl_backlog_first_byte_offset:0",
                    "repl_backlog_histlen:0",
                ]
            else:
                host, port = view.role_master
                lines = [
                    "role:slave",
                    f"master_host:{host}",
                    f"master_port:{port}",
                    "master_link_status:down",
                    "master_last_io_seconds_ago:-1",
                    "master_sync_in_progress:0",
                    "slave_read_repl_offset:0",
                    "slave_repl_offset:0",
                    "master_link_down_since_seconds:1",
                    "slave_priority:100",
                    "slave_read_only:1",
                    "replica_announced:1",
                    "connected_slaves:0",
                    "master_failover_state:no-failover",
                    f"master_replid:{p.replid}",
                    "master_replid2:" + "0" * 40,
                    "master_repl_offset:0",
                    "second_repl_offset:-1",
                    "repl_backlog_active:0",
                    "repl_backlog_size:1048576",
                    "repl_backlog_first_byte_offset:0",
                    "repl_backlog_histlen:0",
                ]
            section("Replication", lines)
        elif name == "cpu":
            section(
                "CPU",
                [
                    "used_cpu_sys:%d.%06d" % (up // 400, (up * 7919) % 1_000_000),
                    "used_cpu_user:%d.%06d" % (up // 600, (up * 104729) % 1_000_000),
                    "used_cpu_sys_children:0.%06d" % ((up * 31) % 1_000_000),
                    "used_cpu_user_children:0.%06d" % ((up * 17) % 1_000_000),
                    "used_cpu_sys_main_thread:%d.%06d" % (up // 400, (up * 7907) % 1_000_000),
                    "used_cpu_user_main_thread:%d.%06d" % (up // 600, (up * 104723) % 1_000_000),
                ],
            )
        elif name == "modules":
            section("Modules", [])
        elif name == "errorstats":
            section("Errorstats", ["errorstat_ERR:count=%d" % (ctx.total_commands // 9 + 1)])
        elif name == "commandstats":
            section(
                "Commandstats",
                [
                    "cmdstat_ping:calls=%d,usec=%d,usec_per_call=0.47,rejected_calls=0,failed_calls=0"
                    % (up // 15, up // 15 * 47 // 100),
                    "cmdstat_info:calls=%d,usec=%d,usec_per_call=61.2,rejected_calls=0,failed_calls=0"
                    % (ctx.total_commands + 3, (ctx.total_commands + 3) * 61),
                ],
            )
        elif name == "latencystats":
            section(
                "Latencystats",
                [
                    "latency_percentiles_usec_ping:p50=0.001,p99=1.003,p99.9=1.003",
                    "latency_percentiles_usec_info:p50=57.343,p99=118.783,p99.9=118.783",
                ],
            )
        elif name == "cluster":
            section("Cluster", ["cluster_enabled:0"])
        elif name == "keyspace":
            section(
                "Keyspace",
                [f"db0:keys={view.keys},expires={view.expires},avg_ttl={view.avg_ttl_ms}"]
                if view.keys
                else [],
            )
    return "\r\n".join(out) + "\r\n" if out else ""

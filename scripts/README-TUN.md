# TUN helper notes

This directory now contains:

- `tun-helper.c` — a tiny privileged helper that opens `/dev/net/tun`, creates a TUN interface, exports `TUN_FD` and `TUN_IFACE`, then execs the provided command.
- `tun-run.sh` — a compile-and-run wrapper around `tun-helper.c`.
- `tun-deploy.sh` — iptables transparent redirection rules for forwarding traffic into `ai-proxy`.
- `tun-cleanup.sh` — cleanup for those iptables rules.

The helper is the prerequisite for a real kernel-TUN bridge. The proxy-side packet engine is still a work in progress.

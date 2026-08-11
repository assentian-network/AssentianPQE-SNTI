# systemd drop-ins

These are not deployed automatically — this repo has no CI/CD (see project
notes); infra changes are applied by hand on each VPS. Files here are kept
for reference/history only. To apply a drop-in, copy it to
`/etc/systemd/system/<service>.service.d/<name>.conf` on the target host and
run `systemctl daemon-reload`.

## miner-wants

Fixes a gap where the mining service(s) would silently stay down after the
node service was stopped and restarted (e.g. during a chain resync). The
miner units already have `Requires=<node>.service`, which propagates STOP
to the miner when the node stops, but never propagates START back. Adding
`Wants=<miner units>` on the node's side closes the loop: starting the node
also starts the miner(s).

| File | Target host | Target unit |
|---|---|---|
| `main-vps-mainnet-node.conf` | Main VPS | `assentian-mainnet-node.service` |
| `kc-seed-node.conf` | Seed-US (Kansas City) | `assentian-seed.service` |
| `sg-seed-node.conf` | Seed-APAC (Singapore) | `assentian-seed.service` |

Deployed and verified live 11 Aug 2026 (tested via stop/start cycle on SG:
miner correctly auto-restarted with the node, sync unaffected).

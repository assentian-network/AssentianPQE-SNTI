ANALISA PROJECT Assentian-PQE (SNTI) — STATUS \& ROADMAP MAINNET



&#x20;   STATUS SAAT INI (26 Jun 2026)



&#x20;   Berjalan

&#x20;   - Testnet node: 456 blocks, aktif mining via stratum

&#x20;   - Stratum server: port 3333 (mining), 3334 (stats) — VERIFIED 18/18 shares

&#x20;   - Explorer: port 80 — LIVE

&#x20;   - RPC: port 39332 (localhost only) — OK



&#x20;   Tidak Berjalan

&#x20;   - assentian-node.service: INACTIVE (crash/stop sejak 04:49 UTC kemarin)

&#x20;     - Penyebab: dual-process bitcoind crash + exit code 1



&#x20;   Kode (PoUW v2)

&#x20;   - src/pouw\_v2.h (190 baris) — Pure XMSS tree-building PoW, sudah terintegrasi

&#x20;   - CheckPoUWv2() di validation.cpp — jalan, debug spam sudah dihapus

&#x20;   - Genesis masih PLACEHOLDER di chainparams.cpp:147 (komentar "do not use mainnet launch")

&#x20;   - Ada 1 file uncommitted penting: pouw\_v2.h (baru ditambahkan)



&#x20;   Infrastruktur

&#x20;   - VPS: 104.234.26.7

&#x20;   - 3 systemd service (node, stratum, explorer)

&#x20;   - Nginx config sudah ke folder Assentian-PQE

&#x20;   - GENESIS MISMATCH: VM rumah \& GitHub masih 0x2001a41a, VPS runtime 0x207fffff (tanpa commit)











&#x20;   CELAH BLOKER KERAS (Wajib sebelum mainnet publik)



&#x20;   #: 1

&#x20;   Celah: Audit keamanan eksternal

&#x20;   Mengapa Harus Diperbaiki: AUDIT.md self-audit Jun 13 terbukti salah. Zero audit independen. Siapapun tidak akan

&#x20;     serius tanpa ini.

&#x20;   ────────────────────────────────────────

&#x20;   #: 2

&#x20;   Celah: Mainnet genesis masih PLACEHOLDER

&#x20;   Mengapa Harus Diperbaiki: Masih 0x207fffff (testnet diff). powLimit nyata dan nonce resmi belum di-mine dan

&#x20;     di-commit.

&#x20;   ────────────────────────────────────────

&#x20;   #: 3

&#x20;   Celah: Uncommitted PoUW v2 code

&#x20;   Mengapa Harus Diperbaiki: pouw\_v2.h + banyak file lain ada di VPS tapi belum di-push. Jika VPS crash, hilang

&#x20;     semua.

&#x20;   ────────────────────────────────────────

&#x20;   #: 4

&#x20;   Celah: Node service crash

&#x20;   Mengapa Harus Diperbaiki: assentian-node.service inactive. Mining testnet berhenti.

&#x20;   ────────────────────────────────────────

&#x20;   #: 5

&#x20;   Celah: Chain reorg PoUW v2 belum pernah diuji

&#x20;   Mengapa Harus Diperbaiki: Reorg handling untuk PoUW v2 tidak punya test. Node bisa split jika ada fork.

&#x20;   ────────────────────────────────────────

&#x20;   #: 6

&#x20;   Celah: Eksternal P2P sync belum GENESIS MATCH

&#x20;   Mengapa Harus Diperbaiki: VM pakai genesis salah. Belum ada node eksternal yang sync penuh via P2P dengan

&#x20;     genesis benar.

&#x20;   ────────────────────────────────────────

&#x20;   #: 7

&#x20;   Celah: Difficulty EMA belum diuji under load

&#x20;   Mengapa Harus Diperbaiki: Alpha=0.1 dengan 1 miner OK, tapi berapa hashrate masuk/keluar belum teruji.

&#x20;   ────────────────────────────────────────

&#x20;   #: 8

&#x20;   Celah: Fuzz testing CheckPoUWv2 tidak ada

&#x20;   Mengapa Harus Diperbaiki: Terima data network secara langsung, malformed input bisa crash node.

&#x20;   ────────────────────────────────────────

&#x20;   #: 9

&#x20;   Celah: Sighash-v2 analisis formal belum

&#x20;   Mengapa Harus Diperbaiki: Teknis closed, tapi bukti formal/pendanaan audit belum.







&#x20;   LANGKAH SELANJUTNYA — URUTAN PRIORITAS



&#x20;   FASE 1 — Stabilkan yang sudah jalan (Hari ini — 1-2 hari)



&#x20;   1. Restart assentian-node.service

&#x20;   bash

&#x20;   sudo systemctl stop assentian-node.service

&#x20;   ps aux | grep bitcoind  # pastikan tidak ada sisa proses

&#x20;   sudo systemctl start assentian-node.service

&#x20;   ./src/bitcoin-cli -testnet -datadir=/root/.assentian\_testnet \\

&#x20;     -rpcuser=user -rpcpassword=password -rpcport=39332 getblockcount





&#x20;   2. Commit \& push semua uncommitted PoUW v2 ke GitHub

&#x20;   - pouw\_v2.h (baru)

&#x20;   - Semua \*.bak\_v2 harus di-commit ulang tanpa .bak (hanya chainparams.cpp, pow.cpp, validation.cpp final)

&#x20;   - Ini #1 prioritas karena jika hilang, progres PoUW v2 hilang



&#x20;   3. Fix genesis mismatch VM rumah

&#x20;   - Sync binary VPS ke VM (scp atau re-clone dari GitHub setelah push)

&#x20;   - VM harus genesis sama: 0616e8b3... (0x207fffff, PoUW v2)

&#x20;   - Test P2P sync via port 39333 dari luar



&#x20;   FASE 2 — Testnet hardening (1-2 minggu)



&#x20;   4. Chain reorg test dengan PoUW v2

&#x20;   bash

&#x20;   Mine 10 block

&#x20;   ./src/bitcoin-cli -testnet ... generatetoaddress 10 "ADDRESS" 200

&#x20;   Invalidate block di height 50 (paksa fork)

&#x20;   ./src/bitcoind -testnet ... invalidateblock <hash\_height\_50>

&#x20;   Reconnect \& verifikasi node pilih chain terpanjang

&#x20;   ./src/bitcoind -testnet ... reconsiderblock <hash\_height\_50>





&#x20;   5. EMA difficulty multi-miner test

&#x20;   - Jalankan 2-3 cpuminer dari beberapa IP

&#x20;   - Tambah/kurangi miner, amati difficulty adjustment stability

&#x20;   - Target: seharusnya 60s per block ±50%



&#x20;   6. Fuzz input CheckPoUWv2

&#x20;   - Kirim crafted block dengan auth\_path malformed, root berukuran salah

&#x20;   - Node harus reject gracefully ( Tidak crash / shutdown )



&#x20;   7. Verifikasi explorer stats fmtHashps

&#x20;   - Sesuai HANDOFF\_NEXT langkah #6 — mudah, \~2 jam



&#x20;   FASE 3 — Mainnet genesis resmi (1-2 minggu)



&#x20;   8. Mine \& patch mainnet genesis

&#x20;   - session\_note.md sudah catat:

&#x20;     - nNonce=24382, nBits=0x1e0fffff, nTime=1782026818

&#x20;     - hash target: 00000fefe6d3b...

&#x20;   - Langkah:

&#x20;     1. Patch chainparams.cpp ke genesis final

&#x20;     2. make -j$(nproc) — WATCH RAM usage (VPS sering DC kalau make -j)

&#x20;     3. Test mine di regtest dulu (port 49332)

&#x20;     4.

&#x20;        rm -rf \~/.snti\_mainnet\_genesis

&#x20;        mkdir -p \~/.snti\_mainnet\_genesis

&#x20;        ./src/bitcoind -datadir=$HOME/.snti\_mainnet\_genesis -rpcport=49332 -daemon

&#x20;        sleep 10

&#x20;        ./src/bitcoin-cli -datadir=$HOME/.snti\_mainnet\_genesis -rpcport=49332 getblockhash 0



&#x20;     5. Harus output: 00000fefe6d3b4368c6b0ac259aa37165861881931fd9fc94aef29ee290bd721

&#x20;     6. Commit + push



&#x20;   9. Salin binary mainnet yang sudah teruji ke \~/.snti\_mainnet/



&#x20;   FASE 4 — Security \& Launch Prep (2-4 minggu)



&#x20;   10. Audit keamanan eksternal

&#x20;   - siapkan scope dokumen (consensus PoUW v2, XMSS implementation, wallet, networking)

&#x20;   - Kontak: Trail of Bits, Halborn, NCC Group (budget $20k-$100k+)

&#x20;   - Bisa mulai dengan competitive audit (Code4rena, Immunefi) dulu untuk budget terbatas



&#x20;   11. Bug bounty program

&#x20;   - Immunefi atau personal program

&#x20;   - Scope: consensus split, key loss, theft

&#x20;   - Budget: $10k-$50k untuk mulai



&#x20;   12. Domain \& DNS seeds

&#x20;   - Daftarkan assentianpqe.com atau yang mirip

&#x20;   - seed.assentianpqe.com pointing to 104.234.26.7

&#x20;   - Uncomment vSeeds di chainparams.cpp



&#x20;   13. Update PROJECT\_STATUS.md \& dokumasikan semua PoUW v2 changes

&#x20;   - Whitepaper v1.2 (termasuk sighash-v2, commitment root, leaf tracking)

&#x20;   - Explorer stats perbaikan

&#x20;   - Mainnet checklist finalisasi



&#x20;   14. Launch mainnet (genesis block)

&#x20;   - Create genesis dengan timestamp resmi

&#x20;   - Mine genesis (mining lock — hanya genesis block yang diproteksi)

&#x20;   - Announce listing CMC/CoinGecko

&#x20;   - Community building (Discord, X/Twitter, Telegram)











&#x20;   SUMMARY KEPUTUSAN CEPAT



&#x20;   Kalau saya kamu dan mau gerak cepat:





&#x20;   HARI INI:

&#x20;   1. Restart assentian-node.service (mining testnet jalan lagi)

&#x20;   2. Commit \& push semua uncommitted PoUW v2 ke GitHub

&#x20;   3. Fix genesis mismatch di rumah



&#x20;   MINGGU INI:

&#x20;   4. Reorg test PoUW v2

&#x20;   5. Difficulty test multi-miner

&#x20;   6. Explorer stats fix

&#x20;   7. Mine mainnet genesis resmi (patch chainparams, build, test, commit)



&#x20;   2-4 MINGGU:

&#x20;   8. Audit eksternal / competitive audit

&#x20;   9. Bug bounty

&#x20;   10. DNS seeds

&#x20;   11. Launch mainnet









&#x20;   Selain itu, ada satu hal teknis: assentian-node.service ada setting StartLimitIntervalSec yang tidak dikenal oleh systemd kamu — harus dihapus dari service file.




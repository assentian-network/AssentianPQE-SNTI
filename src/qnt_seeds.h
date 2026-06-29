// SNTI Seed nodes — hardcoded IPv4 seeds for peer discovery
// Generated for 104.234.26.7 (primary SNTI node — US region)
//
// BIP155 format: 0x01 (IPv4) + 0x04 (addr_len) + 4 bytes IP + 2 bytes port (BE)
//
// ECLIPSE ATTACK MITIGATION: Before mainnet launch, add at minimum 2 more nodes
// in separate AS / geographic regions (EU + APAC). With only 1 seed node, an
// attacker can eclipse any new node by flooding it with their own peers before
// the node reaches our seed. Target: 5+ seed nodes across 3+ different ASes.
//
// To add a new seed node:
//   IP A.B.C.D, port P → {0x01, 0x04, A, B, C, D, (P>>8)&0xff, P&0xff}
//
// Current nodes:
//   104.234.26.7  (AS — US-East, Hetzner/Vultr)

// Mainnet seeds (port 9333)
static const uint8_t chainparams_seed_main[] = {
    0x01,0x04,0x68,0xea,0x1a,0x07,0x24,0x75,  // 104.234.26.7:9333
    // TODO: add EU node   e.g. 0x01,0x04,<EU_IP_4_BYTES>,0x24,0x75
    // TODO: add APAC node e.g. 0x01,0x04,<AP_IP_4_BYTES>,0x24,0x75
};

// Testnet seeds (port 19333)
static const uint8_t chainparams_seed_test[] = {
    0x01,0x04,0x68,0xea,0x1a,0x07,0x4b,0x85,  // 104.234.26.7:19333
    // TODO: add EU testnet node
    // TODO: add APAC testnet node
};

// Regtest seeds (port 29333)
static const uint8_t chainparams_seed_reg[] = {
    0x01,0x04,0x68,0xea,0x1a,0x07,0x72,0x95,  // 104.234.26.7:29333
};

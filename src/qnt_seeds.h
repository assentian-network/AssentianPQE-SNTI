// SNTI Seed nodes — hardcoded IPv4 seeds for peer discovery
//
// BIP155 format: 0x01 (IPv4) + 0x04 (addr_len) + 4 bytes IP + 2 bytes port (BE)
//
// To add a new seed node:
//   IP A.B.C.D, port P → {0x01, 0x04, A, B, C, D, (P>>8)&0xff, P&0xff}
//
// Current nodes (30 Jun 2026):
//   104.234.26.7     (US — primary node + miner)
//   166.88.227.172   (US — Kansas City seed)
//   103.195.190.192  (APAC — Singapore seed)

// Mainnet seeds (port 9333)
static const uint8_t chainparams_seed_main[] = {
    0x01,0x04,0x68,0xea,0x1a,0x07,0x24,0x75,  // 104.234.26.7:9333 (US primary)
    0x01,0x04,0xa6,0x58,0xe3,0xac,0x24,0x75,  // 166.88.227.172:9333 (Kansas City)
    0x01,0x04,0x67,0xc3,0xbe,0xc0,0x24,0x75,  // 103.195.190.192:9333 (Singapore)
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

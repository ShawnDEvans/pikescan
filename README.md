# piKEscan

piKEscan is a high-performance, multi-threaded Python implementation of the classic `ike-scan` architecture. Designed for security researchers and penetration testers, it maps IKEv1 Main Mode and Aggressive Mode transformations, extracts remote gateway identities, and captures high-integrity, Pre-Shared Key (PSK) hashes formatted specifically for seamless cracking in Hashcat (`-m 5400`).

## Features

* **Multi-Threaded Execution:** Built-in thread pool executor handles mass scanning across large target lists cleanly.
* **Dual-Mode Probing:** Supports both standard Main Mode handshake verification and Aggressive Mode profile targeting.
* **Dynamic Response Dissection:** Automatically parses complex, chained ISAKMP payloads based on dynamic boundary lengths.
* **Smart Identity Parsing:** Automatically detects and cleanly interprets both textual (`ID_FQDN`, `ID_KEY_ID`) and raw binary network identifiers (`ID_IPV4_ADDR`, `ID_IPV6_ADDR`).
* **High-Integrity Hash Export:** Structurally formats captured handshake authentications directly into verified, crackable Hashcat signatures using the required `cky_r:cky_i` and `SAib` data sequences.
* **Granular Transform Targeting:** Allows target probing using optimized matrices, exhaustive sets, or an explicit user-defined single transform definition.

---

## Installation

1. Clone the repository and navigate to the project directory:
   ```bash
   cd pikescan
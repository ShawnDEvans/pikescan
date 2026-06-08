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
Note: Because this utility manipulates and injects raw network packets for parts of its Main Mode routines using Scapy, it requires root privileges (sudo) on Linux systems to interact with the raw socket layer.

## Installation

1. Clone the repository and navigate to the project directory:
   ```
   $ cd pikescan
   ```

2. Install the necessary external dependencies using pip:
    ```
    $ pip install -r requirements.txt
    ```

## Usage

```
usage: pikescan.py [-h] [-m {main,aggressive}] [-f FILE] [-t THREADS] [-w TIMEOUT] 
                [-g GROUPS] [-o OUTPUT] [-P HASH_FILE] [-e] [-v] [-d]
                [--enc {DES,3DES,AES-128,AES-192,AES-256}]
                [--hash {MD5,SHA1,SHA256,SHA384,SHA512}]
                [--dh {1,2,5,14,19,20}]
                [targets ...]
```

### Key Arguments & Options
* -m, --mode: Select scanning mode (main or aggressive). Default is main.
* -t, --threads: Number of worker threads for parallel assessment. Default is 10.
* -w, --timeout: Set the network socket timeout in seconds. Default is 1.0.
* -g, --groups: Comma-separated list of group names or a path to a group name dictionary file. Default is cisco.
* -P, --hash-file: Target file path to write captured crackable aggressive mode hashes.
* -e, --enum-transforms: Runs an exhaustive search matrix matching every combination of cipher, hash, and DH group instead of the default optimized profiles.
* -v, --verbose: Enables internal tracking logs and target feedback.
* -d, --debug-packet: Outputs verbose payload sizes and network interaction flags.

### Example
```
$ sudo python pikescan.py -m aggressive 192.168.122.12 --enc AES-128 --hash SHA1 --dh 1 -P target_hash.txt
```

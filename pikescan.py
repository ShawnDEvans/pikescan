import argparse
import json
import os
import random
import socket
import sys
import struct
import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

# --- ANSI Terminal Colors ---
CLR_RESET  = "\033[0m"
CLR_BOLD   = "\033[1m"
CLR_RED    = "\033[91m"
CLR_GREEN  = "\033[92m"
CLR_YELLOW = "\033[93m"
CLR_BLUE   = "\033[94m"
CLR_CYAN   = "\033[96m"

# --- Constants & Primitives ---
CIPHER_PRIMITIVES = [("DES", 1), ("3DES", 5), ("AES-128", 7), ("AES-192", 7), ("AES-256", 7)]
HASH_PRIMITIVES = [("MD5", 1), ("SHA1", 2), ("SHA256", 4), ("SHA384", 5), ("SHA512", 6)]
DH_GROUP_PRIMITIVES = [("Group 1", 1), ("Group 2", 2), ("Group 5", 5), ("Group 14", 14), ("Group 19", 19), ("Group 20", 20)]

OPTIMIZED_AM_PROFILES = [
    ("AES-256", "SHA1", "Group 2",  7, 2, 2),
    ("AES-128", "SHA1", "Group 2",  7, 2, 2),
    ("3DES",    "SHA1", "Group 2",  5, 2, 2),
]

ALL_AM_PROFILES = [
    (enc_name, hash_name, dh_name, enc_id, hash_id, dh_id)
    for enc_name, enc_id in CIPHER_PRIMITIVES
    for hash_name, hash_id in HASH_PRIMITIVES
    for dh_name, dh_id in DH_GROUP_PRIMITIVES
]

# Mapping DH Group to Key Exchange data length in bytes (matches ike-scan specs)
DH_LENGTHS = {
    1: 96,    # Group 1 - 768 bits
    2: 128,   # Group 2 - 1024 bits
    5: 192,   # Group 5 - 1536 bits
    14: 256,  # Group 14 - 2048 bits
    15: 384,  # Group 15 - 3072 bits
    16: 512,  # Group 16 - 4096 bits
    17: 768,  # Group 17 - 6144 bits
    18: 1024, # Group 18 - 8192 bits
    19: 64,   # Group 19 - 256+256 bits
    20: 96,   # Group 20 - 384+384 bits
    21: 132,  # Group 21 - 528+528 bits
}

class ProductionIKEScanner:
    def __init__(self, mode="main", timeout=1, verbose=False, debug_packet=False,
                 group_names=None, threads=10, exhaustive_matrix=False, hash_file=None,
                 custom_transform=None):
        self.mode = mode.lower()
        self.timeout = timeout
        self.verbose = verbose
        self.debug_packet = debug_packet
        self.threads = threads
        self.group_names = group_names if group_names else ["cisco"]
        self.results = []
        self.hash_file = hash_file
        self.write_lock = threading.Lock()

        # Set the profile execution space dynamically based on user configurations
        if custom_transform:
            self.profile_pool = [custom_transform]
        else:
            self.profile_pool = ALL_AM_PROFILES if exhaustive_matrix else OPTIMIZED_AM_PROFILES

    def log(self, message, color=CLR_BLUE):
        if self.verbose:
            print(f"{color}[*]{CLR_RESET} {message}")

    def generate_cookie(self):
        return bytes(random.getrandbits(8) for _ in range(8))

    def probe_main_mode(self, target_ip, profile):
        from scapy.all import IP, UDP, ISAKMP, ISAKMP_payload_SA, ISAKMP_payload_Proposal, ISAKMP_payload_Transform, sr1
        e_name, h_name, d_name, e_val, h_val, d_val = profile
        transform_str = f"Enc:{e_name}, Hash:{h_name}, Auth:PSK, DH:{d_name}"

        packet = (
            IP(dst=target_ip) /
            UDP(sport=500, dport=500) /
            ISAKMP(init_cookie=self.generate_cookie(), exch_type=2, next_payload=1) /
            ISAKMP_payload_SA(next_payload=0) /
            ISAKMP_payload_Proposal(proposal=1, proto=1) /
            ISAKMP_payload_Transform(
                transform_count=1, transform_id=1,
                transforms=[("Encryption", e_val), ("Hash", h_val), ("Authentication", 0x01), ("GroupDesc", d_val)]
            )
        )
        return sr1(packet, timeout=self.timeout, verbose=False), transform_str

    def run_main_mode_scan(self, target_ip):
        from scapy.layers.isakmp import ISAKMP
        findings = {"ip": target_ip, "ikev1_active": False, "matched_transforms": []}
        for profile in self.profile_pool:
            try:
                resp, transform_str = self.probe_main_mode(target_ip, profile)
                if resp and resp.haslayer(ISAKMP):
                    findings["ikev1_active"] = True
                    findings["matched_transforms"].append(transform_str)
                    print(f"{CLR_GREEN}[!] MAIN MATCH:{CLR_RESET} {CLR_BOLD}{target_ip}{CLR_RESET} | {transform_str}")
            except Exception: pass
        return findings

    def build_aggressive_packet(self, target_ip, transform, group_name, id_type):
        enc_id, hash_id, dh_id = transform[3], transform[4], transform[5]

        # Build Attribute Bytes cleanly according to strict ISAKMP definition
        attrs_bytes = b""
        attrs_bytes += struct.pack("!HH", 0x8001, enc_id)  # Encryption Algorithm
        if "AES" in transform[0]:
            if "256" in transform[0]: attrs_bytes += struct.pack("!HH", 0x800E, 256)
            elif "192" in transform[0]: attrs_bytes += struct.pack("!HH", 0x800E, 192)
            elif "128" in transform[0]: attrs_bytes += struct.pack("!HH", 0x800E, 128)
        attrs_bytes += struct.pack("!HH", 0x8002, hash_id) # Hash Algorithm
        attrs_bytes += struct.pack("!HH", 0x8003, 1)       # Authentication Method (PSK)
        attrs_bytes += struct.pack("!HH", 0x8004, dh_id)     # DH Group
        attrs_bytes += struct.pack("!HH", 0x800B, 1)       # Life Type (Seconds)
        attrs_bytes += struct.pack("!HHI", 0x000C, 4, 28800) # Life Duration (TLV format matching ike-scan)

        trans_len = 8 + len(attrs_bytes)
        trans_bytes = struct.pack("!BBHBBH", 0, 0, trans_len, 1, 1, 0) + attrs_bytes

        prop_bytes = struct.pack("!BBHBBBB", 0, 0, 8 + len(trans_bytes), 1, 1, 0, 1) + trans_bytes
        sa_data = struct.pack("!BBHII", 4, 0, 12 + len(prop_bytes), 1, 1) + prop_bytes

        kx_data_len = DH_LENGTHS.get(dh_id, 128)
        ke_data = os.urandom(kx_data_len)
        ke_bytes = struct.pack("!BBH", 10, 0, 4 + len(ke_data)) + ke_data

        init_nonce_data = os.urandom(20)
        nonce_bytes = struct.pack("!BBH", 5, 0, 4 + 20) + init_nonce_data
        id_data = group_name.encode()
        id_bytes = struct.pack("!BBHBBH", 0, 0, 8 + len(id_data), id_type, 0, 0) + id_data

        body_data = bytes(sa_data + ke_bytes + nonce_bytes + id_bytes)
        init_cookie = self.generate_cookie()
        header = struct.pack("!8s8sBBBBII", init_cookie, b"\x00"*8, 1, 0x10, 4, 0, 0, 28 + len(body_data))

        return (header + body_data, ke_data.hex(), sa_data[4:].hex(), init_nonce_data.hex(), init_cookie.hex())

    def run_aggressive_mode_scan(self, target_ip):
        findings = {"ip": target_ip, "aggressive_mode_active": False, "captured_profiles": []}
        identity_matrix = [(2, "ID_FQDN"), (11, "ID_KEY_ID")]

        for id_int, id_name in identity_matrix:
            for transform in self.profile_pool:
                for g_name in self.group_names:
                    try:
                        packet_data = self.build_aggressive_packet(target_ip, transform, g_name, id_type=id_int)
                        payload_bytes, ke_i_hex, sa_i_hex, init_nonce_hex, init_cookie_hex = packet_data
                        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                        sock.settimeout(self.timeout)
                        sock.sendto(payload_bytes, (target_ip, 500))

                        try:
                            resp_bytes, addr = sock.recvfrom(4096)
                            audit = self.dissect_isakmp_response(resp_bytes)

                            transform_str = f"Enc:{transform[0]}, Hash:{transform[1]}, Auth:PSK, DH:{transform[2]}"

                            if self.verbose:
                                print(f"[-] {CLR_BLUE}DEBUG Received {len(resp_bytes)} bytes from {target_ip} | {transform_str}{CLR_RESET}")

                            if audit.get("exchange_type") == 4:
                                findings["aggressive_mode_active"] = True
                                print(f"{CLR_RED}[*] AGGRESSIVE MATCH:{CLR_RESET} {CLR_BOLD}{target_ip}{CLR_RESET} | {transform_str}")
                                print(f"    ├── Gateway ID : {CLR_CYAN}{audit['server_id']}{CLR_RESET}")
                                print(f"    └── Integrity  : {CLR_GREEN}Hash Captured{CLR_RESET}")

                                if self.hash_file:
                                    # Output matching standard Hashcat -m 5400 structural ordering exactly:
                                    # g_xr:g_xi:cky_r:cky_i:sai_b:idir_b:ni_b:nr_b:hash_r
                                    hash_entry = (
                                        f"{audit['ke_resp_hex']}:{ke_i_hex}:{audit['resp_cookie']}:{init_cookie_hex}:"
                                        f"{sa_i_hex}:{audit['id_resp_hex']}:{init_nonce_hex}:{audit['nonce_resp_hex']}:"
                                        f"{audit['hash_resp_hex']}\n"
                                    )
                                    with self.write_lock:
                                        with open(self.hash_file, "a") as hf: hf.write(hash_entry)

                                findings["captured_profiles"].append({"transform": transform_str, "server_id": audit['server_id']})

                        except socket.timeout:
                            pass
                        finally: sock.close()
                    except Exception as e:
                        if self.debug_packet: print(f"[!]{CLR_RED} [ERROR] {CLR_RESET}{e}")
        return findings

    def dissect_isakmp_response(self, resp_bytes):
        """
        Parses ISAKMP response; returns raw payload hex EXCLUDING 4-byte generic payload headers for hashcat.
        Tracks explicit ID Type definitions to cleanly decode text identifiers vs binary endpoints.
        """
        if len(resp_bytes) < 28: return {}

        res = {
            "resp_cookie": resp_bytes[8:16].hex(),
            "exchange_type": resp_bytes[18],
            "server_id": "Unknown",
            "hash_resp_hex": "", "sa_resp_hex": "",
            "id_resp_hex": "", "nonce_resp_hex": "", "ke_resp_hex": ""
        }

        curr_payload_type = resp_bytes[16]
        offset = 28
        total_len = len(resp_bytes)

        while curr_payload_type != 0 and offset < total_len:
            if offset + 4 > total_len: break

            p_len = struct.unpack("!H", resp_bytes[offset+2 : offset+4])[0]
            if p_len < 4 or (offset + p_len) > total_len: break

            payload_raw = resp_bytes[offset : offset+p_len]
            payload_body_raw = payload_raw[4:]
            payload_hex = payload_body_raw.hex()

            # Map payload types (1: SA, 4: KE, 5: ID, 8: Hash, 10: Nonce)
            if curr_payload_type == 1:
                res["sa_resp_hex"] = payload_hex
            elif curr_payload_type == 4:
                res["ke_resp_hex"] = payload_hex
            elif curr_payload_type == 5:
                res["id_resp_hex"] = payload_hex
                if len(payload_raw) > 8:
                    id_type = payload_raw[4]   # Extract the actual ID type indicator
                    id_data = payload_raw[8:]   # Skip the 4-byte generic header + 4-byte ID payload header

                    if id_type == 1 and len(id_data) >= 4:    # ID_IPV4_ADDR
                        try:
                            res["server_id"] = socket.inet_ntoa(id_data[:4])
                        except Exception:
                            res["server_id"] = id_data[:4].hex()
                    elif id_type == 5 and len(id_data) >= 16:  # ID_IPV6_ADDR
                        try:
                            res["server_id"] = socket.inet_ntop(socket.AF_INET6, id_data[:16])
                        except Exception:
                            res["server_id"] = id_data[:16].hex()
                    else:                                      # ID_FQDN, ID_USER_FQDN, ID_KEY_ID
                        res["server_id"] = id_data.decode('utf-8', errors='ignore').strip('\x00')

            elif curr_payload_type == 8:
                res["hash_resp_hex"] = payload_hex
            elif curr_payload_type == 10:
                res["nonce_resp_hex"] = payload_hex

            next_p = resp_bytes[offset]
            curr_payload_type = next_p
            offset += p_len

        return res

    def execute(self, targets):
        self.log(f"Initiating scan for {len(targets)} targets ({self.mode.upper()} mode)...")
        start_time = time.time()
        active_detections = 0
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(self.run_main_mode_scan if self.mode == "main" else self.run_aggressive_mode_scan, ip): ip for ip in targets}
            for future in as_completed(futures):
                data = future.result()
                self.results.append(data)
                if data.get("ikev1_active") or data.get("aggressive_mode_active"): active_detections += 1

        print(f"\n{CLR_BLUE}[*]{CLR_RESET} Assessment complete. Duration: {CLR_BOLD}{time.time()-start_time:.2f}s{CLR_RESET} | Verified Risks: {CLR_RED if active_detections > 0 else CLR_GREEN}{active_detections}{CLR_RESET}")

    def export_json(self, filename):
        with open(filename, 'w') as f: json.dump(self.results, f, indent=4)
        print(f"{CLR_GREEN}[+]{CLR_RESET} Findings written to {CLR_BOLD}{filename}{CLR_RESET}")

def main():
    parser = argparse.ArgumentParser(epilog='piKEscan v1.0 by ShawnDEvans@gmail.com', description='piKEscan is a handy IKE scanning utility.')
    parser.add_argument("-m", "--mode", choices=["main", "aggressive"], default="main")
    parser.add_argument("targets", nargs="*")
    parser.add_argument("-f", "--file")
    parser.add_argument("-t", "--threads", type=int, default=10)
    parser.add_argument("-w", "--timeout", type=float, default=1.0)
    parser.add_argument("-g", "--groups", type=str, default="cisco", help="Define custom group names in a comma delimited list or file")
    parser.add_argument("-o", "--output")
    parser.add_argument("-P", "--hash-file")
    parser.add_argument("-e", "--enum-transforms", action="store_true", help="Enumerate all transforms")
    parser.add_argument("-v", "--verbose", action="store_true")
    parser.add_argument("-d", "--debug-packet", action="store_true")

    # New options for custom explicit transform targeting
    parser.add_argument("--enc", choices=["DES", "3DES", "AES-128", "AES-192", "AES-256"], help="Encryption algorithm for custom transform")
    parser.add_argument("--hash", choices=["MD5", "SHA1", "SHA256", "SHA384", "SHA512"], help="Hash algorithm for custom transform")
    parser.add_argument("--dh", type=int, choices=[1, 2, 5, 14, 19, 20], help="DH Group number for custom transform")
    args = parser.parse_args()

    target_list = list(args.targets)
    if args.file and os.path.exists(args.file):
        with open(args.file, 'r') as f: target_list.extend([l.strip() for l in f if l.strip() and not l.startswith("#")])

    if not target_list:
        print(f"{CLR_RED}[-]{CLR_RESET} No targets specified."); sys.exit(1)

    try:
        with open(args.groups) as groups:
            groups = [ group.strip() for group in groups.readlines() if group.strip() ]
    except FileNotFoundError:
        groups = args.groups.split(',')

    # Check and compile the custom explicit transform parameters if supplied
    custom_transform = None
    if args.enc or args.hash or args.dh:
        if not (args.enc and args.hash and args.dh):
            print(f"{CLR_RED}[-]{CLR_RESET} Error: Custom transform parameters require all flags to be filled simultaneously (--enc, --hash, and --dh).")
            sys.exit(1)

        # Look up corresponding schema IDs matching internal primitives mappings
        enc_id = next(eid for ename, eid in CIPHER_PRIMITIVES if ename == args.enc)
        hash_id = next(hid for hname, hid in HASH_PRIMITIVES if hname == args.hash)
        dh_name = f"Group {args.dh}"
        dh_id = args.dh

        custom_transform = (args.enc, args.hash, dh_name, enc_id, hash_id, dh_id)

    scanner = ProductionIKEScanner(mode=args.mode, timeout=args.timeout, verbose=args.verbose,
                                    debug_packet=args.debug_packet, group_names=groups,
                                    threads=args.threads, exhaustive_matrix=args.enum_transforms,
                                    hash_file=args.hash_file, custom_transform=custom_transform)
    scanner.execute(target_list)
    if args.output: scanner.export_json(args.output)

if __name__ == "__main__":
    main()

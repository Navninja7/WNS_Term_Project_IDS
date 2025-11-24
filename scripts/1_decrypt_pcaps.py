#!/usr/bin/env python3


import os
import subprocess
import sys
from pathlib import Path

# Attack mapping
ATTACKS = {
    1: "Deauth",
    2: "Disass",
    3: "ReAssoc",
    4: "Rogue_AP",
    5: "Krack",
    6: "Kr00k",
    7: "Evil_Twin",
    8: "SQL_Injection",
    9: "SSH",
    10: "Malware",
    11: "SSDP",
    12: "Botnet",
    13: "Website_spoofing"
}

# Key file mappings
KEY_GROUPS = {
    "80211_keys_1-5": [1, 2, 3, 4, 5],
    "80211_keys_6-8": [6, 7, 8],
    "80211_keys_9-13": [9, 10, 11, 12, 13]
}

class PCAPDecryptor:
    def __init__(self, pcap_dir, key_dir, output_dir):
        self.pcap_dir = Path(pcap_dir)
        self.key_dir = Path(key_dir)
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        
    def read_key_file(self, key_file):
        
        key_path = self.key_dir / key_file
        if not key_path.exists():
            print(f"Warning: Key file {key_file} not found!")
            return []
        
        with open(key_path, 'r') as f:
            keys = [line.strip() for line in f if line.strip()]
        return keys
    
    def decrypt_pcap(self, pcap_file, keys, output_file):
        
        print(f"\nDecrypting: {pcap_file}")
        print(f"Output: {output_file}")
        print(f"Using {len(keys)} decryption keys")
        
        # Build tshark command with decryption keys
        cmd = ['tshark', '-r', str(pcap_file), '-w', str(output_file)]
        
        # Add decryption keys
        for key in keys:
            cmd.extend(['-o', f'wlan.enable_decryption:TRUE'])
            cmd.extend(['-o', f'uat:80211_keys:{key}'])
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=3600  # 1 hour timeout
            )
            
            if result.returncode == 0:
                print(f" Successfully decrypted: {pcap_file.name}")
                return True
            else:
                print(f"✗ Error decrypting {pcap_file.name}")
                print(f"Error: {result.stderr}")
                return False
                
        except subprocess.TimeoutExpired:
            print(f"✗ Timeout while decrypting {pcap_file.name}")
            return False
        except Exception as e:
            print(f"✗ Exception: {str(e)}")
            return False
    
    def process_batch(self, key_file, attack_ids):
        
        print(f"\n{'='*60}")
        print(f"Processing batch: {key_file}")
        print(f"Attacks: {[ATTACKS[aid] for aid in attack_ids]}")
        print(f"{'='*60}")
        
        keys = self.read_key_file(key_file)
        if not keys:
            print(f"No keys found in {key_file}, skipping batch")
            return
        
        for attack_id in attack_ids:
            attack_name = ATTACKS[attack_id]
            # Look for PCAP file (common naming patterns)
            possible_names = [
                f"{attack_id}_{attack_name}.pcap",
                f"{attack_id}_{attack_name.lower()}.pcap",
                f"{attack_name}.pcap",
                f"{attack_name.lower()}.pcap"
            ]
            
            pcap_file = None
            for name in possible_names:
                candidate = self.pcap_dir / name
                if candidate.exists():
                    pcap_file = candidate
                    break
            
            if not pcap_file:
                print(f"Warning: PCAP file not found for attack {attack_id} ({attack_name})")
                continue
            
            output_file = self.output_dir / f"{attack_id}_{attack_name}_decrypted.pcap"
            self.decrypt_pcap(pcap_file, keys, output_file)
    
    def process_all(self):
        
        print("Starting AWID3 PCAP Decryption")
        print(f"PCAP Directory: {self.pcap_dir}")
        print(f"Key Directory: {self.key_dir}")
        print(f"Output Directory: {self.output_dir}")
        
        for key_file, attack_ids in KEY_GROUPS.items():
            self.process_batch(key_file, attack_ids)
        
        print("\n" + "="*60)
        print("Decryption complete!")
        print(f"Decrypted files saved to: {self.output_dir}")

def main():
    if len(sys.argv) != 4:
        print("Usage: python 1_decrypt_pcaps.py <pcap_dir> <key_dir> <output_dir>")
        print("\nExample:")
        print("  python 1_decrypt_pcaps.py ./pcaps ./keys ./decrypted_pcaps")
        sys.exit(1)
    
    pcap_dir = sys.argv[1]
    key_dir = sys.argv[2]
    output_dir = sys.argv[3]
    
    decryptor = PCAPDecryptor(pcap_dir, key_dir, output_dir)
    decryptor.process_all()

if __name__ == "__main__":
    main()
#!/usr/bin/env python3


import subprocess
import sys
import csv
from pathlib import Path

s
TSHARK_FIELDS = [
    
    'frame.number',
    'frame.time_epoch',
    'frame.time_delta',
    'frame.time_relative',
    'frame.len',
    'frame.cap_len',
    'frame.protocols',
    
   
    'radiotap.length',
    'radiotap.mactime',
    'radiotap.flags',
    'radiotap.datarate',
    'radiotap.channel.freq',
    'radiotap.channel.flags',
    'radiotap.dbm_antsignal',
    'radiotap.dbm_antnoise',
    'radiotap.antenna',
    'radiotap.flags.cfp',
    'radiotap.flags.preamble',
    'radiotap.flags.wep',
    'radiotap.flags.frag',
    'radiotap.flags.fcs',
    'radiotap.flags.datapad',
    'radiotap.flags.badfcs',
    'radiotap.flags.shortgi',
    
    
    'wlan_radio.duration',
    'wlan_radio.preamble',
    'wlan_radio.phy',
    'wlan_radio.data_rate',
    'wlan_radio.channel',
    'wlan_radio.frequency',
    'wlan_radio.signal_dbm',
    'wlan_radio.noise_dbm',
    'wlan_radio.snr',
    
    
    'wlan.fc.type',
    'wlan.fc.type_subtype',
    'wlan.fc.subtype',
    'wlan.fc.ds',
    'wlan.fc.tods',
    'wlan.fc.fromds',
    'wlan.fc.frag',
    'wlan.fc.retry',
    'wlan.fc.pwrmgt',
    'wlan.fc.moredata',
    'wlan.fc.protected',
    'wlan.fc.order',
    
    
    'wlan.ra',
    'wlan.da',
    'wlan.ta',
    'wlan.sa',
    'wlan.bssid',
    'wlan.addr',
    'wlan.staa',
    
    
    'wlan.duration',
    'wlan.seq',
    'wlan.frag',
    
    
    'wlan.fixed.beacon',
    'wlan.fixed.timestamp',
    'wlan.fixed.capabilities',
    'wlan.fixed.capabilities.ess',
    'wlan.fixed.capabilities.ibss',
    'wlan.fixed.capabilities.privacy',
    'wlan.fixed.status_code',
    'wlan.fixed.reason_code',
    'wlan.fixed.aid',
    'wlan.fixed.current_ap',
    
    
    'wlan.tag.number',
    'wlan.tag.length',
    'wlan.ssid',
    'wlan.tag.vendor.oui.type',
    
    
    'wlan.qos.tid',
    'wlan.qos.priority',
    'wlan.qos.eosp',
    'wlan.qos.ack',
    'wlan.qos.amsdupresent',
    
    
    'wlan.wep.iv',
    'wlan.wep.key',
    'wlan.wep.icv',
    'wlan.tkip.extiv',
    'wlan.ccmp.extiv',
    
    
    'ip.src',
    'ip.dst',
    'ip.proto',
    'ip.len',
    'ip.id',
    'ip.flags',
    'ip.flags.df',
    'ip.flags.mf',
    'ip.frag_offset',
    'ip.ttl',
    'ip.checksum',
    
    
    'ipv6.src',
    'ipv6.dst',
    'ipv6.nxt',
    'ipv6.plen',
    'ipv6.hlim',
    
    
    'tcp.srcport',
    'tcp.dstport',
    'tcp.len',
    'tcp.seq',
    'tcp.ack',
    'tcp.flags',
    'tcp.flags.syn',
    'tcp.flags.ack',
    'tcp.flags.push',
    'tcp.flags.reset',
    'tcp.flags.fin',
    'tcp.window_size',
    'tcp.stream',
    
    
    'udp.srcport',
    'udp.dstport',
    'udp.length',
    'udp.checksum',
    'udp.stream',
    
    
    'http.request',
    'http.request.method',
    'http.request.uri',
    'http.response',
    'http.response.code',
    'http.host',
    'http.user_agent',
    
    
    'dns.qry.name',
    'dns.flags.response',
    'dns.count.queries',
    'dns.count.answers',
    
    
    'arp.opcode',
    'arp.src.proto_ipv4',
    'arp.dst.proto_ipv4',
    'arp.src.hw_mac',
    'arp.dst.hw_mac',
    
    
    'dhcp.type',
    'dhcp.option.dhcp',
    'dhcp.option.requested_ip_address',
    
    
    'icmp.type',
    'icmp.code',
    'icmp.checksum',
    
    
    'eth.src',
    'eth.dst',
    'eth.type',
]

class FeatureExtractor:
    def __init__(self, input_dir, output_dir):
        self.input_dir = Path(input_dir)
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True, parents=True)
        
    def extract_features(self, pcap_file, csv_file):
        
        print(f"\n{'='*70}")
        print(f"Extracting features from: {pcap_file.name}")
        print(f"Output CSV: {csv_file.name}")
        print('='*70)
        
        # Build tshark command
        fields_arg = ' '.join([f'-e {field}' for field in TSHARK_FIELDS])
        cmd = f'tshark -r "{pcap_file}" -T fields {fields_arg} -E header=y -E separator=, -E quote=d -E occurrence=f'
        
        try:
            print("Running tshark (this may take several minutes for large files)...")
            result = subprocess.run(
                cmd,
                shell=True,
                capture_output=True,
                text=True,
                timeout=7200  
            )
            
            if result.returncode == 0:
                
                with open(csv_file, 'w', encoding='utf-8') as f:
                    f.write(result.stdout)
                
                
                with open(csv_file, 'r', encoding='utf-8') as f:
                    line_count = sum(1 for _ in f) - 1  
                
                print(f"\n SUCCESS!")
                print(f"  Extracted packets: {line_count:,}")
                print(f"  Features extracted: {len(TSHARK_FIELDS)}")
                print(f"  Output file: {csv_file}")
                return True
            else:
                print(f"\n✗ ERROR extracting features")
                if result.stderr:
                    error_msg = result.stderr[:1000]
                    print(f"Error message: {error_msg}")
                    
                    
                    if "aren't valid" in result.stderr or "isn't valid" in result.stderr:
                        print("\n  Some field names are not compatible with your tshark version")
                        print("   This is normal - the script will continue with available fields")
                        print("   Attempting extraction with field validation...")
                        
                        # Try with validated fields
                        return self.extract_with_validated_fields(pcap_file, csv_file)
                
                return False
                
        except subprocess.TimeoutExpired:
            print(f"\n✗ TIMEOUT while extracting features (exceeded 2 hours)")
            print("   Try processing this file separately or splitting it")
            return False
        except FileNotFoundError:
            print(f"\n ERROR: tshark not found!")
            print("   Please install Wireshark/tshark:")
            print("   - Ubuntu/Debian: sudo apt-get install tshark")
            print("   - macOS: brew install wireshark")
            print("   - Windows: Download from https://www.wireshark.org/")
            return False
        except Exception as e:
            print(f"\n EXCEPTION: {str(e)}")
            return False
    
    def extract_with_validated_fields(self, pcap_file, csv_file):
        
        print("\n[Validation Mode] Testing available fields...")
        
        # Test which fields are valid
        valid_fields = []
        print("Testing fields (this may take a moment)...")
        
        for i, field in enumerate(TSHARK_FIELDS):
            if i % 20 == 0:
                print(f"  Tested {i}/{len(TSHARK_FIELDS)} fields...", end='\r')
            
            # Test single field
            test_cmd = f'tshark -r "{pcap_file}" -T fields -e {field} -c 1 2>&1'
            try:
                result = subprocess.run(
                    test_cmd,
                    shell=True,
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                
                # Check if field is valid
                if "isn't valid" not in result.stderr and "aren't valid" not in result.stderr:
                    valid_fields.append(field)
            except:
                pass
        
        print(f"\n  Found {len(valid_fields)}/{len(TSHARK_FIELDS)} valid fields")
        
        if len(valid_fields) == 0:
            print("   No valid fields found!")
            return False
        
        # Extract with valid fields only
        print(f"\n  Extracting features with {len(valid_fields)} validated fields...")
        fields_arg = ' '.join([f'-e {field}' for field in valid_fields])
        cmd = f'tshark -r "{pcap_file}" -T fields {fields_arg} -E header=y -E separator=, -E quote=d -E occurrence=f'
        
        try:
            result = subprocess.run(
                cmd,
                shell=True,
                capture_output=True,
                text=True,
                timeout=7200
            )
            
            if result.returncode == 0:
                with open(csv_file, 'w', encoding='utf-8') as f:
                    f.write(result.stdout)
                
                with open(csv_file, 'r', encoding='utf-8') as f:
                    line_count = sum(1 for _ in f) - 1
                
                print(f"\n SUCCESS (with validated fields)!")
                print(f"  Extracted packets: {line_count:,}")
                print(f"  Features extracted: {len(valid_fields)}")
                print(f"  Output file: {csv_file}")
                return True
            else:
                print(f"\n Still failed after validation")
                return False
                
        except Exception as e:
            print(f"\n Exception during validated extraction: {str(e)}")
            return False
    
    def process_all(self):
        
        print("\n" + "="*70)
        print("AWID3 FEATURE EXTRACTION")
        print("="*70)
        print(f"Input Directory:  {self.input_dir}")
        print(f"Output Directory: {self.output_dir}")
        print(f"Features to extract: {len(TSHARK_FIELDS)}")
        print("="*70)
        
        # Find all PCAP files
        pcap_files = sorted(self.input_dir.glob("*.pcap"))
        
        if not pcap_files:
            print("\n ERROR: No PCAP files found in input directory!")
            print(f"   Checked: {self.input_dir}")
            print("   Make sure:")
            print("   1. The directory path is correct")
            print("   2. Files have .pcap extension")
            print("   3. You've run decryption first (1_decrypt_pcaps.py)")
            return
        
        print(f"\nFound {len(pcap_files)} PCAP files to process:")
        for i, pf in enumerate(pcap_files, 1):
            print(f"  {i}. {pf.name}")
        
        # Process each file
        success_count = 0
        failed_files = []
        
        for i, pcap_file in enumerate(pcap_files, 1):
            print(f"\n\n[{i}/{len(pcap_files)}] Processing {pcap_file.name}...")
            
            csv_file = self.output_dir / f"{pcap_file.stem}_features.csv"
            
            if self.extract_features(pcap_file, csv_file):
                success_count += 1
            else:
                failed_files.append(pcap_file.name)
        
        # Final summary
        print("\n\n" + "="*70)
        print("EXTRACTION COMPLETE!")
        print("="*70)
        print(f"Successfully processed: {success_count}/{len(pcap_files)} files")
        
        if success_count > 0:
            print(f"CSV files saved to: {self.output_dir}")
        
        if failed_files:
            print(f"\n Failed files ({len(failed_files)}):")
            for fn in failed_files:
                print(f"   - {fn}")
            print("\nYou may need to:")
            print("  1. Check if these files are corrupted")
            print("  2. Process them individually")
            print("  3. Update tshark to latest version")
        
        if success_count > 0:
            print("\n Successfully extracted features from some files!")
            print("\nNext step:")
            print("  python 3_apply_filters_and_labels.py ./feature_csvs ./labeled_csvs")
        else:
            print("\n✗ All files failed to process")
            print("   Please check your tshark installation and PCAP files")

def main():
    if len(sys.argv) != 3:
        print("="*70)
        print("AWID3 Feature Extraction Script")
        print("="*70)
        print("\nUsage:")
        print("  python 2_extract_features.py <input_pcap_dir> <output_csv_dir>")
        print("\nExample:")
        print("  python 2_extract_features.py ./decrypted_pcaps ./feature_csvs")
        print("\nDescription:")
        print("  Extracts features from decrypted PCAP files using tshark")
        print("  Features include: WLAN, Radiotap, IP, TCP/UDP, HTTP, DNS")
        print("\nRequirements:")
        print("  - tshark/Wireshark must be installed")
        print("  - Input PCAPs should be decrypted first")
        print("="*70)
        sys.exit(1)
    
    input_dir = sys.argv[1]
    output_dir = sys.argv[2]
    
    # Validate input directory
    if not Path(input_dir).exists():
        print(f" ERROR: Input directory does not exist: {input_dir}")
        sys.exit(1)
    
    extractor = FeatureExtractor(input_dir, output_dir)
    extractor.process_all()

if __name__ == "__main__":
    main()
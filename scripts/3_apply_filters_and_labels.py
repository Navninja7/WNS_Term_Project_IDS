#!/usr/bin/env python3
"""
Apply attack-specific filters and add labels to feature CSV files.
Attack traffic gets labeled with attack_id, normal traffic gets label 0.

Usage:
    python 3_apply_filters_and_labels.py <input_csv_dir> <output_csv_dir>

Example:
    python 3_apply_filters_and_labels.py ./feature_csvs ./labeled_csvs
"""

import pandas as pd
import sys
from pathlib import Path
import re
import warnings
warnings.filterwarnings('ignore')


ATTACKS = {
    1: {
        'name': 'Deauth',
        'filter': lambda df: (
            ((df['wlan.fc.type_subtype'] == '0x000a') | (df['wlan.fc.type_subtype'] == '0x000c')) &
            (df['wlan.fc.protected'] == 'False') &
            (df['frame.number'].astype(float) >= 1088022) &
            (df['frame.number'].astype(float) <= 1626254)
        )
    },
    2: {
        'name': 'Disass',
        'filter': lambda df: (
            ((df['wlan.fc.type_subtype'] == '0x000a') | (df['wlan.fc.type_subtype'] == '0x000c')) &
            (df['wlan.fc.protected'] == 'False') &
            (df['frame.number'].astype(float) >= 1404237) &
            (df['frame.number'].astype(float) <= 2013346)
        )
    },
    3: {
        'name': 'ReAssoc',
        'filter': lambda df: (
            ((df['wlan.fc.type_subtype'] == '0x0000') | 
             (df['wlan.fc.type_subtype'] == '0x0002') | 
             (df['wlan.fc.type_subtype'] == '0x0008')) &
            (df['frame.number'].astype(float) >= 1145178) &
            (df['frame.number'].astype(float) <= 1833964) &
            (df['frame.len'].astype(float) <= 301)
        )
    },
    4: {
        'name': 'Rogue_AP',
        'filter': lambda df: (
            (df['wlan.fc.type_subtype'] == '0x0008') &
            (df['frame.number'].astype(float) >= 1198551) &
            (df['frame.number'].astype(float) <= 1973111) &
            (df['frame.len'].astype(float) < 264)
        )
    },
    5: {
        'name': 'Krack',
        'filter': lambda df: (df['wlan_radio.channel'] == '2')
    },
    6: {
        'name': 'Kr00k',
        'filter': lambda df: (
            (df['wlan.fc.type_subtype'] == '0x000a') &
            (df['wlan.fc.protected'] == 'False') &
            (df['frame.number'].astype(float) >= 1555898)
        )
    },
    7: {
        'name': 'Evil_Twin',
        'filter': lambda df: (
            (
                ((df['wlan.fc.type_subtype'] == '0x0008') & (df['frame.len'].astype(float) < 242)) |
                (((df['wlan.fc.type_subtype'] == '0x000a') | 
                  (df['wlan.fc.type_subtype'] == '0x000c') | 
                  (df['wlan.fc.type_subtype'] == '0x0028')) & 
                 (df['wlan.fc.protected'] == 'False'))
            ) &
            (df['frame.number'].astype(float) >= 1420038) &
            (df['frame.number'].astype(float) <= 3778728) &
            ((df['ip.src'] == '192.168.30.1') | 
             (df['ip.dst'] == '192.168.30.1') |
             (df['wlan.addr'].str.contains('0c:9d:92:54:fe:35', na=False)))
        )
    },
    8: {
        'name': 'SQL_Injection',
        'filter': lambda df: (
            ((df['ip.src'] == '192.168.2.248') | (df['ip.dst'] == '192.168.2.248')) &
            (df['frame.number'].astype(float) >= 1484773) &
            (df['frame.number'].astype(float) <= 2589043)
        )
    },
    9: {
        'name': 'SSH',
        'filter': lambda df: (
            ((df['ip.src'] == '192.168.2.248') | (df['ip.dst'] == '192.168.2.248')) &
            (df['frame.number'].astype(float) >= 1356015) &
            (df['frame.number'].astype(float) <= 2440390)
        )
    },
    10: {
        'name': 'Malware',
        'filter': lambda df: (
            ((df['ip.src'] == '192.168.2.248') | (df['ip.dst'] == '192.168.2.248') |
             (df['ip.src'] == '192.168.2.42') | (df['ip.dst'] == '192.168.2.42') |
             (df['ip.src'] == '192.168.2.73') | (df['ip.dst'] == '192.168.2.73') |
             (df['ip.src'] == '192.168.2.41') | (df['ip.dst'] == '192.168.2.41') |
             (df['ip.src'] == '192.168.2.254') | (df['ip.dst'] == '192.168.2.254') |
             (df['ip.src'] == '192.168.2.184') | (df['ip.dst'] == '192.168.2.184') |
             (df['ip.src'] == '192.168.2.190') | (df['ip.dst'] == '192.168.2.190')) &
            ((df['ip.src'] == '192.168.2.130') | (df['ip.dst'] == '192.168.2.130')) &
            (df['frame.number'].astype(float) >= 1021326) &
            (df['frame.number'].astype(float) <= 2310931)
        )
    },
    11: {
        'name': 'SSDP',
        'filter': lambda df: (
            ((df['ip.src'] == '20.50.64.3') | (df['ip.dst'] == '20.50.64.3') |
             (df['ip.src'] == '192.168.2.248') | (df['ip.dst'] == '192.168.2.248')) &
            (df['frame.protocols'].str.contains('ssdp', case=False, na=False)) &
            (df['frame.number'].astype(float) >= 1198154) &
            (df['frame.number'].astype(float) <= 8122583)
        )
    },
    12: {
        'name': 'Botnet',
        'filter': lambda df: (
            ((df['ip.src'] == '192.168.2.248') | (df['ip.dst'] == '192.168.2.248')) &
            ((df['ip.src'].isin(['192.168.2.130', '192.168.2.1', '192.168.2.125', 
                                  '192.168.2.42', '192.168.2.184', '192.168.2.73'])) |
             (df['ip.dst'].isin(['192.168.2.130', '192.168.2.1', '192.168.2.125',
                                 '192.168.2.42', '192.168.2.184', '192.168.2.73']))) &
            (df['frame.number'].astype(float) >= 1135097) &
            (df['frame.number'].astype(float) <= 3325480)
        )
    },
    13: {
        'name': 'Website_spoofing',
        'filter': lambda df: (
            ((df['wlan.sa'].isin(['04:ed:33:e0:24:82', '00:C0:CA:A8:29:56', 
                                   '24:F5:A2:EA:86:C3', '00:C0:CA:A8:26:3E'])) |
             (df['wlan.da'].isin(['04:ed:33:e0:24:82', '00:C0:CA:A8:29:56',
                                   '24:F5:A2:EA:86:C3', '00:C0:CA:A8:26:3E']))) &
            (df['frame.number'].astype(float) >= 16410) &
            (df['frame.number'].astype(float) <= 2668583)
        )
    }
}

class FilterLabeler:
    def __init__(self, input_dir, output_dir):
        self.input_dir = Path(input_dir)
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True, parents=True)
        
    def extract_attack_id(self, filename):
        """Extract attack ID from filename."""
        match = re.match(r'(\d+)_', filename)
        if match:
            return int(match.group(1))
        return None
    
    def apply_filter_and_label(self, csv_file, attack_id):
        """Apply filter and add labels to CSV file."""
        print(f"\n{'='*70}")
        print(f"Processing: {csv_file.name}")
        print('='*70)
        
        attack_info = ATTACKS.get(attack_id)
        
        if not attack_info:
            print(f"✗ ERROR: No attack definition found for ID {attack_id}")
            print(f"   Valid attack IDs: 1-13")
            return False
        
        attack_name = attack_info['name']
        print(f"Attack Type: {attack_name} (ID: {attack_id})")
        
        try:
            
            print("\n[1/4] Reading CSV file...")
            df = pd.read_csv(csv_file, low_memory=False)
            total_packets = len(df)
            total_features = len(df.columns)
            print(f"      Total packets: {total_packets:,}")
            print(f"      Total features: {total_features}")
            
            
            print("\n[2/4] Initializing labels (all set to 0 - normal)...")
            df['label'] = 0
            
            # Apply filter to identify attack traffic
            print(f"\n[3/4] Applying {attack_name} attack filter...")
            
            attack_count = 0
            try:
                # Check if required columns exist
                required_columns = self._get_required_columns(attack_id)
                missing_columns = [col for col in required_columns if col not in df.columns]
                
                if missing_columns:
                    print(f"      ⚠️  WARNING: Missing required columns: {missing_columns}")
                    print(f"      This may happen if features weren't extracted properly")
                    print(f"      All packets will be labeled as normal (0)")
                else:
                    
                    attack_mask = attack_info['filter'](df)
                    attack_count = attack_mask.sum()
                    
                    
                    df.loc[attack_mask, 'label'] = attack_id
                    
                    print(f"       Filter applied successfully")
                
            except Exception as filter_error:
                print(f"      ⚠️  WARNING: Filter application error")
                print(f"      Error: {str(filter_error)}")
                print(f"      All packets will be labeled as normal (0)")
            
            
            print(f"\n[4/4] Labeling complete!")
            print(f"\n      Label Distribution:")
            print(f"      ------------------")
            print(f"      Normal traffic (label=0):  {(total_packets - attack_count):>10,} ({(total_packets-attack_count)/total_packets*100:>5.2f}%)")
            print(f"      Attack traffic (label={attack_id}): {attack_count:>10,} ({attack_count/total_packets*100:>5.2f}%)")
            
            if attack_count == 0:
                print(f"\n      ⚠️  WARNING: No attack packets found!")
                print(f"      Possible reasons:")
                print(f"      1. Attack filter doesn't match this dataset")
                print(f"      2. Frame numbers are different in your PCAP")
                print(f"      3. Required features missing from extraction")
                print(f"      4. This is expected if processing wrong attack file")
            
            
            output_file = self.output_dir / f"{attack_id}_{attack_name}_labeled.csv"
            print(f"\n      Saving labeled dataset...")
            print(f"      Output: {output_file}")
            df.to_csv(output_file, index=False)
            
            
            if output_file.exists():
                file_size_mb = output_file.stat().st_size / (1024 * 1024)
                print(f"      File size: {file_size_mb:.2f} MB")
                print(f"\n SUCCESS: {csv_file.name} processed successfully!")
            else:
                print(f"\n✗ ERROR: Failed to save output file")
                return False
            
            return True
            
        except FileNotFoundError:
            print(f"\n✗ ERROR: File not found: {csv_file}")
            return False
        except pd.errors.EmptyDataError:
            print(f"\n✗ ERROR: CSV file is empty: {csv_file}")
            return False
        except Exception as e:
            print(f"\n✗ ERROR processing {csv_file.name}")
            print(f"   Exception: {str(e)}")
            import traceback
            print(f"\n   Traceback:")
            traceback.print_exc()
            return False
    
    def _get_required_columns(self, attack_id):
        """Get list of required columns for each attack filter."""
        base_cols = ['frame.number', 'frame.len']
        wlan_cols = ['wlan.fc.type_subtype', 'wlan.fc.protected']
        ip_cols = ['ip.src', 'ip.dst']
        
        if attack_id in [1, 2, 6]:  
            return base_cols + wlan_cols
        elif attack_id == 3:  
            return base_cols + wlan_cols
        elif attack_id == 4:  
            return base_cols + wlan_cols
        elif attack_id == 5:  
            return ['wlan_radio.channel']
        elif attack_id == 7:  
            return base_cols + wlan_cols + ip_cols + ['wlan.addr']
        elif attack_id in [8, 9, 10]:  
            return base_cols + ip_cols
        elif attack_id == 11:  
            return base_cols + ip_cols + ['frame.protocols']
        elif attack_id == 12:  
            return base_cols + ip_cols
        elif attack_id == 13:  
            return base_cols + ['wlan.sa', 'wlan.da']
        return base_cols
    
    def process_all(self):
        """Process all feature CSV files."""
        print("\n" + "="*70)
        print("AWID3 FILTER AND LABEL APPLICATION")
        print("="*70)
        print(f"Input Directory:  {self.input_dir}")
        print(f"Output Directory: {self.output_dir}")
        print("="*70)
        
        
        csv_files = sorted(self.input_dir.glob("*_features.csv"))
        
        if not csv_files:
            print("\n✗ ERROR: No feature CSV files found!")
            print(f"   Checked: {self.input_dir}")
            print("   Make sure:")
            print("   1. The directory path is correct")
            print("   2. Files have '_features.csv' suffix")
            print("   3. You've run feature extraction first (2_extract_features.py)")
            return
        
        print(f"\nFound {len(csv_files)} CSV files to process:")
        for i, cf in enumerate(csv_files, 1):
            attack_id = self.extract_attack_id(cf.name)
            attack_name = ATTACKS.get(attack_id, {}).get('name', 'Unknown')
            print(f"  {i}. {cf.name} → Attack {attack_id}: {attack_name}")
        
       
        success_count = 0
        failed_files = []
        
        for i, csv_file in enumerate(csv_files, 1):
            print(f"\n\n{'#'*70}")
            print(f"# [{i}/{len(csv_files)}] Processing {csv_file.name}")
            print(f"{'#'*70}")
            
            attack_id = self.extract_attack_id(csv_file.name)
            
            if attack_id is None:
                print(f"\n⚠️  WARNING: Could not extract attack ID from filename")
                print(f"   Filename should start with attack ID (1-13)")
                print(f"   Example: 1_Deauth_decrypted_features.csv")
                failed_files.append(csv_file.name)
                continue
            
            if self.apply_filter_and_label(csv_file, attack_id):
                success_count += 1
            else:
                failed_files.append(csv_file.name)
        
        
        print("\n\n" + "="*70)
        print("LABELING COMPLETE!")
        print("="*70)
        print(f"Successfully processed: {success_count}/{len(csv_files)} files")
        print(f"Labeled CSV files saved to: {self.output_dir}")
        
        if failed_files:
            print(f"\n⚠️  Failed files ({len(failed_files)}):")
            for fn in failed_files:
                print(f"   - {fn}")
        else:
            print("\n All files processed successfully!")
            print("\nYour labeled datasets are ready for ML training!")
            print("\nNext steps:")
            print("  1. Validate datasets: python 6_validate_dataset.py ./labeled_csvs")
            print("  2. Analyze statistics: python 4_dataset_statistics.py ./labeled_csvs")
            print("  3. Combine datasets: python 5_combine_datasets.py ./labeled_csvs ./ml_datasets --split")

def main():
    if len(sys.argv) != 3:
        print("="*70)
        print("AWID3 Filter and Label Application Script")
        print("="*70)
        print("\nUsage:")
        print("  python 3_apply_filters_and_labels.py <input_csv_dir> <output_csv_dir>")
        print("\nExample:")
        print("  python 3_apply_filters_and_labels.py ./feature_csvs ./labeled_csvs")
        print("\nDescription:")
        print("  Applies attack-specific filters to feature CSVs and adds labels:")
        print("  - Label 0: Normal/benign traffic")
        print("  - Label 1-13: Specific attack type")
        print("\nSupported Attacks:")
        for attack_id, info in sorted(ATTACKS.items()):
            print(f"  {attack_id:2d}. {info['name']}")
        print("="*70)
        sys.exit(1)
    
    input_dir = sys.argv[1]
    output_dir = sys.argv[2]
    
    
    if not Path(input_dir).exists():
        print(f" ERROR: Input directory does not exist: {input_dir}")
        sys.exit(1)
    
    labeler = FilterLabeler(input_dir, output_dir)
    labeler.process_all()

if __name__ == "__main__":
    main()
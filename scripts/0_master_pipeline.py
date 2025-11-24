#!/usr/bin/env python3

import sys
import subprocess
from pathlib import Path
import argparse

def run_command(cmd, description):
    
    print(f"\n{'='*70}")
    print(f"STEP: {description}")
    print(f"{'='*70}")
    print(f"Command: {' '.join(cmd)}")
    print()
    
    try:
        result = subprocess.run(cmd, check=True)
        print(f"\n {description} completed successfully!")
        return True
    except subprocess.CalledProcessError as e:
        print(f"\n✗ {description} failed with error code {e.returncode}")
        return False
    except Exception as e:
        print(f"\n✗ Unexpected error during {description}: {str(e)}")
        return False

class AWID3Pipeline:
    def __init__(self, pcap_dir, key_dir, output_base_dir, skip_decryption=False):
        self.pcap_dir = Path(pcap_dir)
        self.key_dir = Path(key_dir)
        self.output_base_dir = Path(output_base_dir)
        self.skip_decryption = skip_decryption
        
        
        self.decrypted_dir = self.output_base_dir / "1_decrypted_pcaps"
        self.features_dir = self.output_base_dir / "2_feature_csvs"
        self.labeled_dir = self.output_base_dir / "3_labeled_csvs"
        
        for d in [self.decrypted_dir, self.features_dir, self.labeled_dir]:
            d.mkdir(parents=True, exist_ok=True)
    
    def validate_inputs(self):
        
        print("Validating inputs...")
        
        if not self.skip_decryption:
            if not self.pcap_dir.exists():
                print(f"✗ PCAP directory not found: {self.pcap_dir}")
                return False
            
            if not self.key_dir.exists():
                print(f"✗ Key directory not found: {self.key_dir}")
                return False
            
            pcap_count = len(list(self.pcap_dir.glob("*.pcap")))
            key_count = len(list(self.key_dir.glob("80211_keys_*")))
            
            print(f" Found {pcap_count} PCAP files")
            print(f" Found {key_count} key files")
            
            if pcap_count == 0:
                print("✗ No PCAP files found!")
                return False
        else:
            print("Skipping decryption - using existing decrypted PCAPs")
            if not self.decrypted_dir.exists():
                print(f"✗ Decrypted PCAP directory not found: {self.decrypted_dir}")
                return False
        
        return True
    
    def run_pipeline(self):
        
        print("\n" + "="*70)
        print("AWID3 DATASET PROCESSING PIPELINE")
        print("="*70)
        print(f"PCAP Directory: {self.pcap_dir}")
        print(f"Key Directory: {self.key_dir}")
        print(f"Output Directory: {self.output_base_dir}")
        print(f"Skip Decryption: {self.skip_decryption}")
        
        if not self.validate_inputs():
            print("\n✗ Input validation failed. Aborting pipeline.")
            return False
        
        steps_completed = 0
        total_steps = 3 if not self.skip_decryption else 2
        
        
        if not self.skip_decryption:
            if run_command(
                ['python3', '1_decrypt_pcaps.py', 
                 str(self.pcap_dir), str(self.key_dir), str(self.decrypted_dir)],
                "Step 1: PCAP Decryption"
            ):
                steps_completed += 1
            else:
                print("\n✗ Pipeline failed at decryption step")
                return False
        
        
        if run_command(
            ['python3', '2_extract_features.py',
             str(self.decrypted_dir), str(self.features_dir)],
            f"Step {2 if not self.skip_decryption else 1}: Feature Extraction"
        ):
            steps_completed += 1
        else:
            print("\n✗ Pipeline failed at feature extraction step")
            return False
        
        
        if run_command(
            ['python3', '3_apply_filters_and_labels.py',
             str(self.features_dir), str(self.labeled_dir)],
            f"Step {3 if not self.skip_decryption else 2}: Filter and Label Application"
        ):
            steps_completed += 1
        else:
            print("\n✗ Pipeline failed at labeling step")
            return False
        
        
        print("\n" + "="*70)
        print("Generating dataset statistics...")
        run_command(
            ['python3', '4_dataset_statistics.py', str(self.labeled_dir)],
            "Dataset Analysis (Optional)"
        )
        
        
        print("\n" + "="*70)
        print("PIPELINE COMPLETED SUCCESSFULLY!")
        print("="*70)
        print(f" {steps_completed}/{total_steps} core steps completed")
        print(f"\nOutput locations:")
        if not self.skip_decryption:
            print(f"  1. Decrypted PCAPs: {self.decrypted_dir}")
        print(f"  2. Feature CSVs:    {self.features_dir}")
        print(f"  3. Labeled CSVs:    {self.labeled_dir}")
        print(f"\nYou can now use the labeled CSV files for IDS training!")
        
        return True

def main():
    parser = argparse.ArgumentParser(
        description='AWID3 Dataset Processing Pipeline',
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    
    parser.add_argument('pcap_dir', help='Directory containing raw PCAP files')
    parser.add_argument('key_dir', help='Directory containing decryption key files')
    parser.add_argument('output_dir', help='Base output directory for processed data')
    parser.add_argument('--skip-decryption', action='store_true',
                       help='Skip decryption step (use existing decrypted PCAPs)')
    
    args = parser.parse_args()
    
    pipeline = AWID3Pipeline(
        args.pcap_dir,
        args.key_dir,
        args.output_dir,
        args.skip_decryption
    )
    
    success = pipeline.run_pipeline()
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()

#!/usr/bin/env python3


import pandas as pd
import sys
from pathlib import Path
import argparse
from sklearn.model_selection import train_test_split

class DatasetCombiner:
    def __init__(self, input_dir, output_dir):
        self.input_dir = Path(input_dir)
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        
        self.attack_names = {
            0: 'Normal',
            1: 'Deauth',
            2: 'Disass',
            3: 'ReAssoc',
            4: 'Rogue_AP',
            5: 'Krack',
            6: 'Kr00k',
            7: 'Evil_Twin',
            8: 'SQL_Injection',
            9: 'SSH',
            10: 'Malware',
            11: 'SSDP',
            12: 'Botnet',
            13: 'Website_spoofing'
        }
    
    def load_labeled_csvs(self, attack_ids=None):
        
        print("\nLoading labeled CSV files...")
        
        csv_files = sorted(self.input_dir.glob("*_labeled.csv"))
        
        if not csv_files:
            print("✗ No labeled CSV files found!")
            return None
        
        dataframes = []
        total_packets = 0
        
        for csv_file in csv_files:
            
            attack_id = int(csv_file.name.split('_')[0])
            
            
            if attack_ids and attack_id not in attack_ids:
                continue
            
            attack_name = self.attack_names.get(attack_id, f'Unknown_{attack_id}')
            
            print(f"  Loading: {csv_file.name}")
            try:
                df = pd.read_csv(csv_file, low_memory=False)
                packets = len(df)
                total_packets += packets
                
                
                label_dist = df['label'].value_counts().sort_index()
                print(f"    Packets: {packets:,}")
                for label, count in label_dist.items():
                    label_name = self.attack_names.get(int(label), f'Label_{label}')
                    print(f"      {label_name}: {count:,} ({count/packets*100:.1f}%)")
                
                dataframes.append(df)
                
            except Exception as e:
                print(f"    ✗ Error loading {csv_file.name}: {str(e)}")
        
        if not dataframes:
            print("✗ No data loaded!")
            return None
        
        print(f"\n Loaded {len(dataframes)} files with {total_packets:,} total packets")
        
        
        print("\nCombining datasets...")
        combined_df = pd.concat(dataframes, ignore_index=True)
        
        return combined_df
    
    def balance_dataset(self, df, samples_per_class=None):
        """Balance dataset by sampling equal number from each class."""
        print("\nBalancing dataset...")
        
        if samples_per_class is None:
            
            label_counts = df['label'].value_counts()
            samples_per_class = label_counts.min()
            print(f"  Using minimum class size: {samples_per_class:,} samples")
        
        balanced_dfs = []
        
        for label in df['label'].unique():
            label_df = df[df['label'] == label]
            
            if len(label_df) >= samples_per_class:
                sampled = label_df.sample(n=samples_per_class, random_state=42)
            else:
                sampled = label_df
                print(f"  Warning: {self.attack_names.get(int(label))} has only {len(label_df)} samples")
            
            balanced_dfs.append(sampled)
        
        balanced_df = pd.concat(balanced_dfs, ignore_index=True)
        
        print(f" Balanced dataset: {len(balanced_df):,} packets")
        print("\nClass distribution:")
        for label, count in balanced_df['label'].value_counts().sort_index().items():
            label_name = self.attack_names.get(int(label), f'Label_{label}')
            print(f"  {label_name}: {count:,}")
        
        return balanced_df
    
    def create_train_test_split(self, df, test_size=0.3, output_prefix='dataset'):
        """Split dataset into training and testing sets."""
        print(f"\nCreating train/test split (test_size={test_size})...")
        
        X = df.drop('label', axis=1)
        y = df['label']
        
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=test_size, random_state=42, stratify=y
        )
        
        
        train_df = pd.concat([X_train, y_train], axis=1)
        test_df = pd.concat([X_test, y_test], axis=1)
        
        
        train_file = self.output_dir / f"{output_prefix}_train.csv"
        test_file = self.output_dir / f"{output_prefix}_test.csv"
        
        print(f"  Saving training set: {train_file}")
        train_df.to_csv(train_file, index=False)
        print(f"    Training samples: {len(train_df):,}")
        
        print(f"  Saving testing set: {test_file}")
        test_df.to_csv(test_file, index=False)
        print(f"    Testing samples: {len(test_df):,}")
        
        print("\n Train/test split complete!")
        
        return train_df, test_df
    
    def save_full_dataset(self, df, filename='combined_dataset.csv'):
        """Save the full combined dataset."""
        output_file = self.output_dir / filename
        print(f"\nSaving full dataset: {output_file}")
        df.to_csv(output_file, index=False)
        print(f" Saved {len(df):,} packets")

def main():
    parser = argparse.ArgumentParser(
        description='Combine and prepare AWID3 datasets for ML training',
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    
    parser.add_argument('input_dir', help='Directory containing labeled CSV files')
    parser.add_argument('output_dir', help='Output directory for combined datasets')
    parser.add_argument('--attacks', nargs='+', type=int,
                       help='Specific attack IDs to include (e.g., --attacks 1 2 3)')
    parser.add_argument('--balance', action='store_true',
                       help='Balance dataset (equal samples per class)')
    parser.add_argument('--samples', type=int,
                       help='Number of samples per class (with --balance)')
    parser.add_argument('--split', action='store_true',
                       help='Create train/test split')
    parser.add_argument('--test-size', type=float, default=0.3,
                       help='Test set size (default: 0.3)')
    parser.add_argument('--output-prefix', default='dataset',
                       help='Prefix for output files (default: dataset)')
    
    args = parser.parse_args()
    
    combiner = DatasetCombiner(args.input_dir, args.output_dir)
    
    
    df = combiner.load_labeled_csvs(attack_ids=args.attacks)
    
    if df is None:
        print("\n✗ Failed to load data")
        sys.exit(1)
    
    
    if args.balance:
        df = combiner.balance_dataset(df, samples_per_class=args.samples)
    
    
    combiner.save_full_dataset(df, f"{args.output_prefix}_full.csv")
    
    
    if args.split:
        combiner.create_train_test_split(
            df, 
            test_size=args.test_size,
            output_prefix=args.output_prefix
        )
    
    print("\n" + "="*60)
    print("Dataset preparation complete!")
    print(f"Output directory: {args.output_dir}")
    print("="*60)

if __name__ == "__main__":
    main()
#!/usr/bin/env python3


import pandas as pd
import numpy as np
import sys
from pathlib import Path
import warnings
warnings.filterwarnings('ignore')

class DatasetValidator:
    def __init__(self, csv_dir):
        self.csv_dir = Path(csv_dir)
        self.issues_found = []
        self.warnings_found = []
        
    def check_file_exists(self, csv_file):
        
        if not csv_file.exists():
            self.issues_found.append(f"File not found: {csv_file}")
            return False
        
        try:
            df = pd.read_csv(csv_file, nrows=1)
            return True
        except Exception as e:
            self.issues_found.append(f"Cannot read {csv_file.name}: {str(e)}")
            return False
    
    def check_labels(self, df, csv_file):
        
        print(f"\n  Checking labels...")
        
        if 'label' not in df.columns:
            self.issues_found.append(f"{csv_file.name}: Missing 'label' column")
            return False
        
        # Check for null labels
        null_labels = df['label'].isnull().sum()
        if null_labels > 0:
            self.issues_found.append(
                f"{csv_file.name}: {null_labels} rows with null labels"
            )
        
        # Check label distribution
        label_counts = df['label'].value_counts().sort_index()
        
        # Must have label 0 (normal traffic)
        if 0 not in label_counts.index:
            self.warnings_found.append(
                f"{csv_file.name}: No normal traffic (label 0) found"
            )
        
        # Must have at least one attack label
        attack_labels = [l for l in label_counts.index if l != 0]
        if not attack_labels:
            self.warnings_found.append(
                f"{csv_file.name}: No attack labels found"
            )
        
        # Check for extreme imbalance (>99% one class)
        for label, count in label_counts.items():
            pct = count / len(df) * 100
            if pct > 99:
                self.warnings_found.append(
                    f"{csv_file.name}: Extreme imbalance - label {label} is {pct:.1f}%"
                )
        
        print(f"    Label distribution: {dict(label_counts)}")
        return True
    
    def check_features(self, df, csv_file):
        
        print(f"\n  Checking features...")
        
        # Check for constant columns (no variance)
        constant_cols = []
        for col in df.columns:
            if col == 'label':
                continue
            
            try:
                if df[col].nunique() == 1:
                    constant_cols.append(col)
            except:
                pass
        
        if constant_cols:
            self.warnings_found.append(
                f"{csv_file.name}: {len(constant_cols)} constant features (no variance)"
            )
            if len(constant_cols) <= 5:
                print(f"    Constant features: {constant_cols}")
        
        
        missing_pct = (df.isnull().sum() / len(df) * 100).round(2)
        high_missing = missing_pct[missing_pct > 90]
        
        if len(high_missing) > 0:
            self.warnings_found.append(
                f"{csv_file.name}: {len(high_missing)} features with >90% missing values"
            )
            if len(high_missing) <= 5:
                print(f"    High missing features: {list(high_missing.index)}")
        
        
        duplicates = df.duplicated().sum()
        if duplicates > 0:
            dup_pct = duplicates / len(df) * 100
            self.warnings_found.append(
                f"{csv_file.name}: {duplicates} duplicate rows ({dup_pct:.1f}%)"
            )
        
        print(f"    Total features: {len(df.columns) - 1}")
        print(f"    Constant features: {len(constant_cols)}")
        print(f"    High missing (>90%): {len(high_missing)}")
        print(f"    Duplicate rows: {duplicates}")
        
        return True
    
    def check_data_types(self, df, csv_file):
        
        print(f"\n  Checking data types...")
        
        
        dtype_counts = df.dtypes.value_counts()
        print(f"    Data types: {dict(dtype_counts)}")
        
        
        object_cols = df.select_dtypes(include=['object']).columns.tolist()
        if 'label' in object_cols:
            object_cols.remove('label')
        
        if len(object_cols) > 0:
            self.warnings_found.append(
                f"{csv_file.name}: {len(object_cols)} object/string columns (may need encoding)"
            )
            if len(object_cols) <= 10:
                print(f"    Object columns: {object_cols[:10]}")
        
        return True
    
    def check_frame_numbers(self, df, csv_file):
        
        print(f"\n  Checking frame numbers...")
        
        if 'frame.number' in df.columns:
            try:
                frame_nums = pd.to_numeric(df['frame.number'], errors='coerce')
                
                
                missing_frames = frame_nums.isnull().sum()
                if missing_frames > 0:
                    self.warnings_found.append(
                        f"{csv_file.name}: {missing_frames} missing frame numbers"
                    )
                
                
                if not frame_nums.isnull().all():
                    min_frame = frame_nums.min()
                    max_frame = frame_nums.max()
                    print(f"    Frame range: {min_frame:.0f} to {max_frame:.0f}")
            except:
                pass
        else:
            self.warnings_found.append(f"{csv_file.name}: No 'frame.number' column")
        
        return True
    
    def validate_file(self, csv_file):
        """Run all validation checks on a single file."""
        print(f"\n{'='*60}")
        print(f"Validating: {csv_file.name}")
        print('='*60)
        
        if not self.check_file_exists(csv_file):
            return False
        
        try:
            df = pd.read_csv(csv_file, low_memory=False)
            print(f"  Total rows: {len(df):,}")
            print(f"  Total columns: {len(df.columns)}")
            
            self.check_labels(df, csv_file)
            self.check_features(df, csv_file)
            self.check_data_types(df, csv_file)
            self.check_frame_numbers(df, csv_file)
            
            print(f"\n Validation complete for {csv_file.name}")
            return True
            
        except Exception as e:
            self.issues_found.append(f"{csv_file.name}: Validation error - {str(e)}")
            return False
    
    def print_summary(self):
        """Print validation summary."""
        print(f"\n{'='*60}")
        print("VALIDATION SUMMARY")
        print('='*60)
        
        if self.issues_found:
            print(f"\nCRITICAL ISSUES ({len(self.issues_found)}):")
            for i, issue in enumerate(self.issues_found, 1):
                print(f"  {i}. {issue}")
        else:
            print("\n No critical issues found!")
        
        if self.warnings_found:
            print(f"\nWARNINGS ({len(self.warnings_found)}):")
            for i, warning in enumerate(self.warnings_found, 1):
                print(f"  {i}. {warning}")
        else:
            print("\n No warnings!")
        
        print(f"\n{'='*60}")
        
        if self.issues_found:
            print("VALIDATION FAILED - Please fix critical issues")
            return False
        elif self.warnings_found:
            print("  VALIDATION PASSED WITH WARNINGS - Review warnings before training")
            return True
        else:
            print("VALIDATION PASSED - Dataset is ready for ML training!")
            return True
    
    def validate_all(self):
        """Validate all CSV files in directory."""
        print("Starting Dataset Validation")
        print(f"Directory: {self.csv_dir}")
        print("="*60)
        
        csv_files = sorted(self.csv_dir.glob("*_labeled.csv"))
        
        if not csv_files:
            print("\n No labeled CSV files found!")
            return False
        
        print(f"\nFound {len(csv_files)} files to validate")
        
        validated = 0
        for csv_file in csv_files:
            if self.validate_file(csv_file):
                validated += 1
        
        print(f"\n{'='*60}")
        print(f"Processed {validated}/{len(csv_files)} files")
        
        return self.print_summary()

def main():
    if len(sys.argv) != 2:
        print("Usage: python 6_validate_dataset.py <labeled_csv_dir>")
        print("\nExample:")
        print("  python 6_validate_dataset.py ./labeled_csvs")
        sys.exit(1)
    
    csv_dir = sys.argv[1]
    
    validator = DatasetValidator(csv_dir)
    success = validator.validate_all()
    
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()
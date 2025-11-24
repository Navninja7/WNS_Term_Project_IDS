#!/usr/bin/env python3


import pandas as pd
import sys
from pathlib import Path
import json

class DatasetAnalyzer:
    def __init__(self, input_dir):
        self.input_dir = Path(input_dir)
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
    
    def analyze_csv(self, csv_file):
        """Analyze a single CSV file."""
        print(f"\n{'='*60}")
        print(f"Analyzing: {csv_file.name}")
        print('='*60)
        
        try:
            df = pd.read_csv(csv_file, low_memory=False)
            
            stats = {
                'filename': csv_file.name,
                'total_packets': len(df),
                'features': len(df.columns) - 1,  
                'label_distribution': {},
                'missing_values': {},
                'memory_usage_mb': df.memory_usage(deep=True).sum() / (1024 * 1024)
            }
            
            
            if 'label' in df.columns:
                label_counts = df['label'].value_counts().sort_index()
                for label, count in label_counts.items():
                    label_name = self.attack_names.get(int(label), f'Unknown_{label}')
                    stats['label_distribution'][label_name] = {
                        'count': int(count),
                        'percentage': float(count / len(df) * 100)
                    }
                
                print(f"\nLabel Distribution:")
                for label_name, info in stats['label_distribution'].items():
                    print(f"  {label_name:20s}: {info['count']:8d} ({info['percentage']:5.2f}%)")
            
            
            missing = df.isnull().sum()
            missing_pct = (missing / len(df) * 100).round(2)
            
            
            features_with_missing = missing[missing > 0].sort_values(ascending=False)
            
            if len(features_with_missing) > 0:
                print(f"\nTop 10 Features with Missing Values:")
                for feature in features_with_missing.head(10).index:
                    stats['missing_values'][feature] = {
                        'count': int(missing[feature]),
                        'percentage': float(missing_pct[feature])
                    }
                    print(f"  {feature:40s}: {missing[feature]:8d} ({missing_pct[feature]:5.2f}%)")
            else:
                print("\n No missing values found!")
            
            print(f"\nDataset Summary:")
            print(f"  Total packets: {stats['total_packets']:,}")
            print(f"  Total features: {stats['features']}")
            print(f"  Memory usage: {stats['memory_usage_mb']:.2f} MB")
            
            return stats
            
        except Exception as e:
            print(f"✗ Error analyzing {csv_file.name}: {str(e)}")
            return None
    
    def generate_summary_report(self, all_stats):
        
        print("\n" + "="*60)
        print("OVERALL DATASET SUMMARY")
        print("="*60)
        
        total_packets = sum(s['total_packets'] for s in all_stats if s)
        total_memory = sum(s['memory_usage_mb'] for s in all_stats if s)
        
        # Aggregate label distribution
        label_totals = {}
        for stats in all_stats:
            if stats and 'label_distribution' in stats:
                for label, info in stats['label_distribution'].items():
                    if label not in label_totals:
                        label_totals[label] = 0
                    label_totals[label] += info['count']
        
        print(f"\nTotal Packets Across All Datasets: {total_packets:,}")
        print(f"Total Memory Usage: {total_memory:.2f} MB")
        print(f"Number of Attack Types: {len(label_totals) - 1}")  # Exclude 'Normal'
        
        print(f"\nAggregated Label Distribution:")
        for label in sorted(label_totals.keys()):
            count = label_totals[label]
            pct = count / total_packets * 100
            print(f"  {label:20s}: {count:10,} ({pct:5.2f}%)")
        
        return {
            'total_packets': total_packets,
            'total_memory_mb': total_memory,
            'datasets_processed': len([s for s in all_stats if s]),
            'label_distribution': label_totals
        }
    
    def save_report(self, all_stats, summary, output_file):
        
        report = {
            'summary': summary,
            'individual_datasets': all_stats
        }
        
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"\n Full report saved to: {output_file}")
    
    def process_all(self):
        
        print("Starting Dataset Analysis")
        print(f"Input Directory: {self.input_dir}")
        print("="*60)
        
        csv_files = sorted(self.input_dir.glob("*_labeled.csv"))
        
        if not csv_files:
            print("No labeled CSV files found!")
            return
        
        print(f"Found {len(csv_files)} CSV files to analyze")
        
        all_stats = []
        for csv_file in csv_files:
            stats = self.analyze_csv(csv_file)
            all_stats.append(stats)
        
        
        summary = self.generate_summary_report(all_stats)
        
        
        report_file = self.input_dir / "dataset_analysis_report.json"
        self.save_report(all_stats, summary, report_file)
        
        print("\n" + "="*60)
        print("Analysis complete!")

def main():
    if len(sys.argv) != 2:
        print("Usage: python 4_dataset_statistics.py <labeled_csv_dir>")
        print("\nExample:")
        print("  python 4_dataset_statistics.py ./labeled_csvs")
        sys.exit(1)
    
    input_dir = sys.argv[1]
    
    analyzer = DatasetAnalyzer(input_dir)
    analyzer.process_all()

if __name__ == "__main__":
    main()
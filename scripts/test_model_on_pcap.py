#!/usr/bin/env python3


import sys
import pickle
import pandas as pd
import numpy as np
from pathlib import Path
from datetime import datetime
import json
import warnings
warnings.filterwarnings('ignore')

try:
    from scapy.all import *
except ImportError:
    print("Error: scapy not installed!")
    print("Install: pip install scapy")
    sys.exit(1)

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import seaborn as sns

class PCAPTester:
    def __init__(self, model_path, scaler_path, pcap_path, output_dir='test_results'):
        """Initialize PCAP tester."""
        self.pcap_path = Path(pcap_path)
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True, parents=True)
        
        
        print(f"Loading model from {model_path}...")
        with open(model_path, 'rb') as f:
            self.model = pickle.load(f)
        print(" Model loaded")
        
        
        print(f"Loading scaler from {scaler_path}...")
        with open(scaler_path, 'rb') as f:
            self.scaler = pickle.load(f)
        print(" Scaler loaded")
        
        
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
        
        self.predictions = []
        self.confidences = []
        self.timestamps = []
        
    def extract_features_from_packet(self, packet):
        """Extract features from a single packet."""
        features = {}
        
        try:
            features['frame.len'] = len(packet)
            features['frame.time'] = float(packet.time)
            
            if packet.haslayer(Dot11):
                dot11 = packet[Dot11]
                features['wlan.fc.type'] = dot11.type
                features['wlan.fc.subtype'] = dot11.subtype
                features['wlan.fc.type_subtype'] = (dot11.type << 4) | dot11.subtype
                features['wlan.fc.tods'] = int(dot11.FCfield & 0x01 != 0)
                features['wlan.fc.fromds'] = int(dot11.FCfield & 0x02 != 0)
                features['wlan.fc.retry'] = int(dot11.FCfield & 0x08 != 0)
                features['wlan.fc.protected'] = int(dot11.FCfield & 0x40 != 0)
                features['wlan.sa'] = dot11.addr2 if dot11.addr2 else ''
                features['wlan.da'] = dot11.addr1 if dot11.addr1 else ''
            
            if packet.haslayer(RadioTap):
                radiotap = packet[RadioTap]
                features['radiotap.dbm_antsignal'] = radiotap.dBm_AntSignal if hasattr(radiotap, 'dBm_AntSignal') else 0
            
            if packet.haslayer(IP):
                ip = packet[IP]
                features['ip.src'] = ip.src
                features['ip.dst'] = ip.dst
                features['ip.proto'] = ip.proto
                features['ip.ttl'] = ip.ttl
            
            if packet.haslayer(TCP):
                tcp = packet[TCP]
                features['tcp.srcport'] = tcp.sport
                features['tcp.dstport'] = tcp.dport
                features['tcp.flags.syn'] = int(tcp.flags & 0x02 != 0)
            
            if packet.haslayer(UDP):
                udp = packet[UDP]
                features['udp.srcport'] = udp.sport
                features['udp.dstport'] = udp.dport
        
        except Exception as e:
            pass
        
        return features
    
    def process_pcap(self):
        """Process PCAP file and make predictions."""
        print(f"\n{'='*70}")
        print(f"Processing PCAP: {self.pcap_path.name}")
        print('='*70)
        
        
        print("Reading packets...")
        try:
            packets = rdpcap(str(self.pcap_path))
            total_packets = len(packets)
            print(f" Loaded {total_packets:,} packets")
        except Exception as e:
            print(f"✗ Error reading PCAP: {str(e)}")
            return False
        
        
        print("\nProcessing packets...")
        for i, packet in enumerate(packets):
            if (i + 1) % 1000 == 0:
                print(f"  Processed {i+1:,}/{total_packets:,} packets...", end='\r')
            
            features = self.extract_features_from_packet(packet)
            
            if features:
                df = pd.DataFrame([features])
                for col in df.select_dtypes(include=['object']).columns:
                    df[col] = pd.factorize(df[col])[0]
                df = df.fillna(0)
                
                try:
                    X_scaled = self.scaler.transform(df)
                    prediction = self.model.predict(X_scaled)[0]
                    
                    if hasattr(self.model, 'predict_proba'):
                        confidence = self.model.predict_proba(X_scaled)[0][prediction]
                    else:
                        confidence = 1.0
                    
                    self.predictions.append(int(prediction))
                    self.confidences.append(float(confidence))
                    self.timestamps.append(float(packet.time))
                
                except Exception as e:
                    self.predictions.append(0)
                    self.confidences.append(0.0)
                    self.timestamps.append(float(packet.time))
        
        print(f"\n Processed all {total_packets:,} packets")
        return True
    
    def generate_report(self):
        
        print("\n" + "="*70)
        print("GENERATING REPORT")
        print("="*70)
        
        if not self.predictions:
            print("✗ No predictions to report")
            return
        
        
        total = len(self.predictions)
        predictions_array = np.array(self.predictions)
        
        attack_counts = {}
        for pred in predictions_array:
            attack_name = self.attack_names.get(int(pred), f'Unknown_{pred}')
            attack_counts[attack_name] = attack_counts.get(attack_name, 0) + 1
        
        
        print(f"\nDetection Summary:")
        print(f"  Total Packets:    {total:,}")
        print(f"  Normal Traffic:   {attack_counts.get('Normal', 0):,} ({attack_counts.get('Normal', 0)/total*100:.2f}%)")
        print(f"  Attack Traffic:   {(total - attack_counts.get('Normal', 0)):,} ({(total - attack_counts.get('Normal', 0))/total*100:.2f}%)")
        
        print(f"\nAttack Type Distribution:")
        for attack, count in sorted(attack_counts.items(), key=lambda x: x[1], reverse=True):
            if attack != 'Normal' and count > 0:
                print(f"  {attack:20s}: {count:>8,} ({count/total*100:>6.2f}%)")
        
        
        report = {
            'pcap_file': str(self.pcap_path),
            'timestamp': datetime.now().isoformat(),
            'total_packets': total,
            'attack_counts': attack_counts,
            'predictions': self.predictions,
            'confidences': self.confidences,
            'timestamps': self.timestamps
        }
        
        report_path = self.output_dir / f"{self.pcap_path.stem}_report.json"
        with open(report_path, 'w') as f:
            json.dump(report, f, indent=2)
        print(f"\n Detailed report saved: {report_path}")
        
        
        self.generate_plots(attack_counts)
    
    def generate_plots(self, attack_counts):
        """Generate visualization plots."""
        print("\nGenerating plots...")
        
        
        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(15, 6))
        
        
        filtered_attacks = {k: v for k, v in attack_counts.items() if v > 0}
        
        colors = plt.cm.Set3(np.linspace(0, 1, len(filtered_attacks)))
        ax1.pie(filtered_attacks.values(), labels=filtered_attacks.keys(), autopct='%1.1f%%',
               colors=colors, startangle=90)
        ax1.set_title('Attack Type Distribution', fontweight='bold', fontsize=14)
        
        
        attacks = list(filtered_attacks.keys())
        counts = list(filtered_attacks.values())
        
        bars = ax2.bar(range(len(attacks)), counts, color=colors)
        ax2.set_xlabel('Attack Type', fontweight='bold')
        ax2.set_ylabel('Count', fontweight='bold')
        ax2.set_title('Attack Detection Counts', fontweight='bold', fontsize=14)
        ax2.set_xticks(range(len(attacks)))
        ax2.set_xticklabels(attacks, rotation=45, ha='right')
        ax2.grid(axis='y', alpha=0.3)
        
        
        for bar in bars:
            height = bar.get_height()
            ax2.text(bar.get_x() + bar.get_width()/2., height,
                    f'{int(height):,}',
                    ha='center', va='bottom', fontsize=9)
        
        plt.tight_layout()
        plot_path = self.output_dir / f"{self.pcap_path.stem}_distribution.png"
        plt.savefig(plot_path, dpi=300, bbox_inches='tight')
        plt.close()
        print(f" Distribution plot saved: {plot_path}")
        
        
        if len(self.timestamps) > 0:
            self.plot_timeline()
    
    def plot_timeline(self):
        """Plot attack detection timeline."""
        fig, ax = plt.subplots(figsize=(15, 6))
        
        
        df = pd.DataFrame({
            'timestamp': self.timestamps,
            'prediction': self.predictions
        })
        
        
        df['time'] = df['timestamp'] - df['timestamp'].min()
        
        
        for attack_id, attack_name in self.attack_names.items():
            attack_data = df[df['prediction'] == attack_id]
            if len(attack_data) > 0:
                ax.scatter(attack_data['time'], [attack_id] * len(attack_data),
                          label=attack_name, alpha=0.6, s=10)
        
        ax.set_xlabel('Time (seconds)', fontweight='bold', fontsize=12)
        ax.set_ylabel('Attack Type', fontweight='bold', fontsize=12)
        ax.set_title('Attack Detection Timeline', fontweight='bold', fontsize=14)
        ax.set_yticks(list(self.attack_names.keys()))
        ax.set_yticklabels(list(self.attack_names.values()))
        ax.legend(bbox_to_anchor=(1.05, 1), loc='upper left')
        ax.grid(True, alpha=0.3)
        
        plt.tight_layout()
        timeline_path = self.output_dir / f"{self.pcap_path.stem}_timeline.png"
        plt.savefig(timeline_path, dpi=300, bbox_inches='tight')
        plt.close()
        print(f" Timeline plot saved: {timeline_path}")
    
    def run(self):
        """Run complete test."""
        if self.process_pcap():
            self.generate_report()
            
            print("\n" + "="*70)
            print("TESTING COMPLETE!")
            print("="*70)
            print(f" Results saved to: {self.output_dir}")

def main():
    if len(sys.argv) != 4:
        print("="*70)
        print("Test ML Model on PCAP File")
        print("="*70)
        print("\nUsage:")
        print("  python test_model_on_pcap.py <model_path> <scaler_path> <pcap_file>")
        print("\nExample:")
        print("  python test_model_on_pcap.py ./models/random_forest_model.pkl ./models/scaler.pkl test.pcap")
        print("\nOutput:")
        print("  - Detection report (JSON)")
        print("  - Distribution plots")
        print("  - Timeline visualization")
        print("="*70)
        sys.exit(1)
    
    model_path = sys.argv[1]
    scaler_path = sys.argv[2]
    pcap_path = sys.argv[3]
    
    # Verify files
    for path, name in [(model_path, 'Model'), (scaler_path, 'Scaler'), (pcap_path, 'PCAP')]:
        if not Path(path).exists():
            print(f"✗ Error: {name} file not found: {path}")
            sys.exit(1)
    
    tester = PCAPTester(model_path, scaler_path, pcap_path)
    tester.run()

if __name__ == "__main__":
    main()
#!/usr/bin/env python3


import sys
import pickle
import numpy as np
import pandas as pd
from pathlib import Path
from datetime import datetime
import json
import time
from collections import deque
import warnings
warnings.filterwarnings('ignore')

try:
    from scapy.all import *
except ImportError:
    print("Error: scapy not installed!")
    print("Install: pip install scapy")
    sys.exit(1)

class RealtimeIDS:
    def __init__(self, model_path, scaler_path, interface, alert_log='alerts.log'):
        """Initialize real-time IDS."""
        self.interface = interface
        self.alert_log = Path(alert_log)
        
        
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
        
        
        self.packet_count = 0
        self.alert_count = 0
        self.attack_stats = {name: 0 for name in self.attack_names.values()}
        self.recent_alerts = deque(maxlen=100)
        
        
        self.start_time = datetime.now()
        
        print(f"\n{'='*70}")
        print("REAL-TIME IDS INITIALIZED")
        print('='*70)
        print(f"Interface: {self.interface}")
        print(f"Model: {Path(model_path).name}")
        print(f"Alert Log: {self.alert_log}")
        print('='*70)
    
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
                features['wlan.fc.pwrmgt'] = int(dot11.FCfield & 0x10 != 0)
                features['wlan.fc.moredata'] = int(dot11.FCfield & 0x20 != 0)
                features['wlan.fc.protected'] = int(dot11.FCfield & 0x40 != 0)
                
                
                features['wlan.sa'] = dot11.addr2 if dot11.addr2 else ''
                features['wlan.da'] = dot11.addr1 if dot11.addr1 else ''
                features['wlan.ra'] = dot11.addr1 if dot11.addr1 else ''
                
                
                if dot11.type == 0:  
                    if dot11.subtype == 8:  
                        features['wlan.fixed.beacon'] = 1
                    if dot11.subtype == 10:  
                        features['wlan.fc.type_subtype'] = 10
                    if dot11.subtype == 12:  
                        features['wlan.fc.type_subtype'] = 12
            
            
            if packet.haslayer(RadioTap):
                radiotap = packet[RadioTap]
                features['radiotap.dbm_antsignal'] = radiotap.dBm_AntSignal if hasattr(radiotap, 'dBm_AntSignal') else 0
                features['radiotap.channel.freq'] = radiotap.ChannelFrequency if hasattr(radiotap, 'ChannelFrequency') else 0
            
            
            if packet.haslayer(IP):
                ip = packet[IP]
                features['ip.src'] = ip.src
                features['ip.dst'] = ip.dst
                features['ip.proto'] = ip.proto
                features['ip.len'] = ip.len
                features['ip.ttl'] = ip.ttl
            
            
            if packet.haslayer(TCP):
                tcp = packet[TCP]
                features['tcp.srcport'] = tcp.sport
                features['tcp.dstport'] = tcp.dport
                features['tcp.flags.syn'] = int(tcp.flags & 0x02 != 0)
                features['tcp.flags.ack'] = int(tcp.flags & 0x04 != 0)
                features['tcp.flags.fin'] = int(tcp.flags & 0x01 != 0)
                features['tcp.flags.reset'] = int(tcp.flags & 0x04 != 0)
            
            
            if packet.haslayer(UDP):
                udp = packet[UDP]
                features['udp.srcport'] = udp.sport
                features['udp.dstport'] = udp.dport
                features['udp.length'] = udp.len
            
        except Exception as e:
            
            pass
        
        return features
    
    def prepare_features_for_model(self, features_dict):
        """Convert extracted features to format expected by model."""
        
        
        df = pd.DataFrame([features_dict])
        
        
        for col in df.select_dtypes(include=['object']).columns:
            df[col] = pd.factorize(df[col])[0]
        
        
        df = df.fillna(0)
        
        return df
    
    def predict_packet(self, packet):
        """Predict if packet is malicious."""
        try:
            
            features = self.extract_features_from_packet(packet)
            
            if not features:
                return None, None
            
            
            df = self.prepare_features_for_model(features)
            
            
            X_scaled = self.scaler.transform(df)
            
            
            prediction = self.model.predict(X_scaled)[0]
            
            
            if hasattr(self.model, 'predict_proba'):
                probabilities = self.model.predict_proba(X_scaled)[0]
                confidence = probabilities[prediction]
            else:
                confidence = 1.0
            
            return int(prediction), confidence
            
        except Exception as e:
            return None, None
    
    def generate_alert(self, packet, prediction, confidence):
        """Generate alert for detected attack."""
        timestamp = datetime.now()
        attack_name = self.attack_names.get(prediction, f'Unknown_{prediction}')
        
        alert = {
            'timestamp': timestamp.isoformat(),
            'attack_type': attack_name,
            'attack_id': int(prediction),
            'confidence': float(confidence),
            'packet_info': {}
        }
        
        
        if packet.haslayer(Dot11):
            dot11 = packet[Dot11]
            alert['packet_info']['src_mac'] = dot11.addr2
            alert['packet_info']['dst_mac'] = dot11.addr1
            alert['packet_info']['type'] = dot11.type
            alert['packet_info']['subtype'] = dot11.subtype
        
        if packet.haslayer(IP):
            ip = packet[IP]
            alert['packet_info']['src_ip'] = ip.src
            alert['packet_info']['dst_ip'] = ip.dst
        
        
        self.log_alert(alert)
        
        
        self.alert_count += 1
        self.attack_stats[attack_name] += 1
        self.recent_alerts.append(alert)
        
        
        self.print_alert(alert)
    
    def log_alert(self, alert):
        """Log alert to file."""
        with open(self.alert_log, 'a') as f:
            f.write(json.dumps(alert) + '\n')
    
    def print_alert(self, alert):
        """Print alert to console."""
        print(f"\n{'!'*70}")
        print(f" ALERT DETECTED!")
        print('!'*70)
        print(f"Time:       {alert['timestamp']}")
        print(f"Attack:     {alert['attack_type']} (ID: {alert['attack_id']})")
        print(f"Confidence: {alert['confidence']:.2%}")
        
        if 'src_mac' in alert['packet_info']:
            print(f"Source MAC: {alert['packet_info']['src_mac']}")
            print(f"Dest MAC:   {alert['packet_info']['dst_mac']}")
        
        if 'src_ip' in alert['packet_info']:
            print(f"Source IP:  {alert['packet_info']['src_ip']}")
            print(f"Dest IP:    {alert['packet_info']['dst_ip']}")
        
        print('!'*70)
    
    def packet_handler(self, packet):
        """Handle each captured packet."""
        self.packet_count += 1
        
        
        prediction, confidence = self.predict_packet(packet)
        
        
        if prediction is not None and prediction != 0:
            self.generate_alert(packet, prediction, confidence)
        
        
        if self.packet_count % 100 == 0:
            self.print_statistics()
    
    def print_statistics(self):
        """Print real-time statistics."""
        uptime = (datetime.now() - self.start_time).total_seconds()
        pps = self.packet_count / uptime if uptime > 0 else 0
        
        print(f"\n{'='*70}")
        print(f"Statistics (Packets: {self.packet_count:,} | Alerts: {self.alert_count:,} | Rate: {pps:.1f} pps)")
        print('='*70)
        
        if self.alert_count > 0:
            print("Attack Distribution:")
            for attack, count in sorted(self.attack_stats.items(), key=lambda x: x[1], reverse=True):
                if count > 0:
                    pct = count / self.alert_count * 100
                    print(f"  {attack:20s}: {count:>5,} ({pct:>5.1f}%)")
    
    def start_capture(self):
        """Start capturing packets in real-time."""
        print(f"\n{'='*70}")
        print(f"STARTING REAL-TIME CAPTURE ON {self.interface}")
        print(f"Press Ctrl+C to stop")
        print('='*70 + "\n")
        
        try:
            
            sniff(
                iface=self.interface,
                prn=self.packet_handler,
                store=False  
            )
        except KeyboardInterrupt:
            print("\n\nStopping capture...")
            self.print_final_statistics()
        except Exception as e:
            print(f"\nError during capture: {str(e)}")
            print("\nMake sure:")
            print("  1. Interface is in monitor mode (for WiFi)")
            print("  2. You have root/admin privileges")
            print("  3. Interface name is correct")
    
    def print_final_statistics(self):
        """Print final statistics."""
        uptime = (datetime.now() - self.start_time).total_seconds()
        
        print(f"\n{'='*70}")
        print("FINAL STATISTICS")
        print('='*70)
        print(f"Total Runtime:     {uptime:.1f} seconds")
        print(f"Total Packets:     {self.packet_count:,}")
        print(f"Total Alerts:      {self.alert_count:,}")
        print(f"Average Rate:      {self.packet_count/uptime:.1f} packets/second")
        print(f"Detection Rate:    {self.alert_count/self.packet_count*100:.2f}%")
        
        if self.alert_count > 0:
            print(f"\nAttack Distribution:")
            for attack, count in sorted(self.attack_stats.items(), key=lambda x: x[1], reverse=True):
                if count > 0:
                    pct = count / self.alert_count * 100
                    print(f"  {attack:20s}: {count:>5,} ({pct:>5.1f}%)")
        
        print(f"\n Alerts saved to: {self.alert_log}")
        print('='*70)

def main():
    if len(sys.argv) != 4:
        print("="*70)
        print("Real-time Intrusion Detection System")
        print("="*70)
        print("\nUsage:")
        print("  sudo python realtime_ids.py <model_path> <scaler_path> <interface>")
        print("\nExample:")
        print("  sudo python realtime_ids.py ./models/random_forest_model.pkl ./models/scaler.pkl wlan0mon")
        print("\nNotes:")
        print("  - Requires root/admin privileges")
        print("  - WiFi interface must be in monitor mode")
        print("  - Use 'iwconfig' or 'ip link' to check interface name")
        print("\nTo put interface in monitor mode:")
        print("  sudo airmon-ng start wlan0")
        print("="*70)
        sys.exit(1)
    
    model_path = sys.argv[1]
    scaler_path = sys.argv[2]
    interface = sys.argv[3]
    
    
    if not Path(model_path).exists():
        print(f"Error: Model file not found: {model_path}")
        sys.exit(1)
    
    if not Path(scaler_path).exists():
        print(f"Error: Scaler file not found: {scaler_path}")
        sys.exit(1)
    
    
    ids = RealtimeIDS(model_path, scaler_path, interface)
    
    
    ids.start_capture()

if __name__ == "__main__":
    main()
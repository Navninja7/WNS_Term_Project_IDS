#!/usr/bin/env python3
"""
Enhanced Rogue AP and Evil Twin Detection System.
Combines ML predictions with heuristic detection methods.

Usage:
    sudo python detect_rogue_evil_twin.py <model_path> <scaler_path> <interface> <config_file>

Example:
    sudo python detect_rogue_evil_twin.py ./models/random_forest_model.pkl ./models/scaler.pkl wlan0mon authorized_aps.json
"""

import sys
import pickle
import pandas as pd
import json
from pathlib import Path
from datetime import datetime
from collections import defaultdict, deque
import warnings
warnings.filterwarnings('ignore')

try:
    from scapy.all import *
except ImportError:
    print("✗ Error: scapy not installed!")
    sys.exit(1)

class RogueAPDetector:
    def __init__(self, model_path, scaler_path, interface, config_path):
        """Initialize Rogue AP and Evil Twin detector."""
        self.interface = interface
        self.alert_log = Path('rogue_ap_alerts.log')
        
        # Load ML model
        print(f"Loading model from {model_path}...")
        with open(model_path, 'rb') as f:
            self.model = pickle.load(f)
        
        with open(scaler_path, 'rb') as f:
            self.scaler = pickle.load(f)
        print("✓ Model loaded")
        
        # Load authorized APs configuration
        self.authorized_aps = self.load_authorized_aps(config_path)
        
        # Tracking structures
        self.ap_database = {}  # BSSID -> AP info
        self.ssid_to_bssids = defaultdict(set)  # SSID -> set of BSSIDs
        self.deauth_counters = defaultdict(int)  # Track deauth attempts
        self.beacon_intervals = defaultdict(list)  # Track beacon timing
        self.signal_strengths = defaultdict(list)  # Track signal strength
        
        # Statistics
        self.packet_count = 0
        self.rogue_ap_count = 0
        self.evil_twin_count = 0
        self.alerts = deque(maxlen=100)
        self.start_time = datetime.now()
        
        print(f"\n{'='*70}")
        print("ROGUE AP & EVIL TWIN DETECTION SYSTEM")
        print('='*70)
        print(f"Interface:       {self.interface}")
        print(f"Authorized APs:  {len(self.authorized_aps)}")
        print(f"Alert Log:       {self.alert_log}")
        print('='*70)
    
    def load_authorized_aps(self, config_path):
        """Load list of authorized APs."""
        if not Path(config_path).exists():
            print(f"\n⚠️  Warning: Config file not found: {config_path}")
            print("Creating default config...")
            
            default_config = {
                "authorized_aps": [
                    {
                        "ssid": "YourNetworkName",
                        "bssid": "aa:bb:cc:dd:ee:ff",
                        "description": "Main Office AP"
                    }
                ]
            }
            
            with open(config_path, 'w') as f:
                json.dump(default_config, f, indent=2)
            
            print(f"✓ Created: {config_path}")
            print("  Please edit this file with your authorized APs!")
            return default_config['authorized_aps']
        
        with open(config_path, 'r') as f:
            config = json.load(f)
        
        print(f"\n✓ Loaded {len(config['authorized_aps'])} authorized APs:")
        for ap in config['authorized_aps']:
            print(f"  - {ap['ssid']} ({ap['bssid']})")
        
        return config['authorized_aps']
    
    def is_authorized(self, ssid, bssid):
        """Check if AP is authorized."""
        for ap in self.authorized_aps:
            if ap['ssid'] == ssid and ap['bssid'].lower() == bssid.lower():
                return True
        return False
    
    def extract_features(self, packet):
        """Extract features from packet."""
        features = {}
        
        try:
            features['frame.len'] = len(packet)
            features['frame.time'] = float(packet.time) if hasattr(packet, 'time') else 0
            
            if packet.haslayer(Dot11):
                dot11 = packet[Dot11]
                features['wlan.fc.type'] = dot11.type
                features['wlan.fc.subtype'] = dot11.subtype
                features['wlan.fc.type_subtype'] = (dot11.type << 4) | dot11.subtype
                features['wlan.fc.protected'] = int(dot11.FCfield & 0x40 != 0)
                features['wlan.sa'] = dot11.addr2 if dot11.addr2 else ''
                features['wlan.da'] = dot11.addr1 if dot11.addr1 else ''
            
            if packet.haslayer(RadioTap):
                radiotap = packet[RadioTap]
                features['radiotap.dbm_antsignal'] = radiotap.dBm_AntSignal if hasattr(radiotap, 'dBm_AntSignal') else 0
        
        except Exception as e:
            pass
        
        return features
    
    def ml_predict(self, packet):
        """Get ML prediction."""
        try:
            features = self.extract_features(packet)
            if not features:
                return None, None
            
            df = pd.DataFrame([features])
            for col in df.select_dtypes(include=['object']).columns:
                df[col] = pd.factorize(df[col])[0]
            df = df.fillna(0)
            
            X_scaled = self.scaler.transform(df)
            prediction = self.model.predict(X_scaled)[0]
            
            if hasattr(self.model, 'predict_proba'):
                confidence = self.model.predict_proba(X_scaled)[0][prediction]
            else:
                confidence = 1.0
            
            return int(prediction), float(confidence)
        
        except Exception as e:
            return None, None
    
    def analyze_beacon(self, packet):
        """Analyze beacon frame for rogue AP detection."""
        if not packet.haslayer(Dot11Beacon):
            return None
        
        try:
            bssid = packet[Dot11].addr3
            ssid = packet[Dot11Elt].info.decode('utf-8', errors='ignore')
            
            # Get signal strength
            signal = None
            if packet.haslayer(RadioTap) and hasattr(packet[RadioTap], 'dBm_AntSignal'):
                signal = packet[RadioTap].dBm_AntSignal
            
            # Update AP database
            if bssid not in self.ap_database:
                self.ap_database[bssid] = {
                    'ssid': ssid,
                    'first_seen': datetime.now(),
                    'last_seen': datetime.now(),
                    'beacon_count': 0,
                    'signal_strengths': [],
                    'authorized': self.is_authorized(ssid, bssid)
                }
            
            ap_info = self.ap_database[bssid]
            ap_info['last_seen'] = datetime.now()
            ap_info['beacon_count'] += 1
            
            if signal:
                ap_info['signal_strengths'].append(signal)
                # Keep only last 100 readings
                ap_info['signal_strengths'] = ap_info['signal_strengths'][-100:]
            
            # Track SSID to BSSID mapping
            self.ssid_to_bssids[ssid].add(bssid)
            
            # Check for Evil Twin (duplicate SSID)
            if len(self.ssid_to_bssids[ssid]) > 1:
                # Multiple BSSIDs with same SSID detected!
                return self.detect_evil_twin(ssid, bssid, ap_info)
            
            # Check for Rogue AP (unauthorized)
            if not ap_info['authorized']:
                return self.detect_rogue_ap(ssid, bssid, ap_info)
        
        except Exception as e:
            pass
        
        return None
    
    def analyze_deauth(self, packet):
        """Analyze deauthentication frames."""
        if not packet.haslayer(Dot11Deauth):
            return None
        
        try:
            bssid = packet[Dot11].addr3
            
            # Count deauth frames
            self.deauth_counters[bssid] += 1
            
            # If high rate of deauth (possible Evil Twin attack)
            if self.deauth_counters[bssid] > 10:  # 10 deauths detected
                ssid = self.ap_database.get(bssid, {}).get('ssid', 'Unknown')
                
                return {
                    'type': 'evil_twin_deauth_storm',
                    'ssid': ssid,
                    'bssid': bssid,
                    'deauth_count': self.deauth_counters[bssid],
                    'severity': 'HIGH',
                    'description': f'Deauthentication storm detected from {bssid}'
                }
        
        except Exception as e:
            pass
        
        return None
    
    def detect_rogue_ap(self, ssid, bssid, ap_info):
        """Detect rogue AP."""
        return {
            'type': 'rogue_ap',
            'ssid': ssid,
            'bssid': bssid,
            'first_seen': ap_info['first_seen'].isoformat(),
            'beacon_count': ap_info['beacon_count'],
            'avg_signal': sum(ap_info['signal_strengths']) / len(ap_info['signal_strengths']) if ap_info['signal_strengths'] else None,
            'severity': 'MEDIUM',
            'description': f'Unauthorized AP detected: {ssid} ({bssid})'
        }
    
    def detect_evil_twin(self, ssid, bssid, ap_info):
        """Detect Evil Twin AP."""
        all_bssids = self.ssid_to_bssids[ssid]
        authorized_bssids = [ap['bssid'] for ap in self.authorized_aps if ap['ssid'] == ssid]
        
        # Check if this BSSID is the unauthorized one
        if bssid.lower() not in [b.lower() for b in authorized_bssids]:
            return {
                'type': 'evil_twin',
                'ssid': ssid,
                'fake_bssid': bssid,
                'legitimate_bssids': authorized_bssids,
                'all_detected_bssids': list(all_bssids),
                'beacon_count': ap_info['beacon_count'],
                'avg_signal': sum(ap_info['signal_strengths']) / len(ap_info['signal_strengths']) if ap_info['signal_strengths'] else None,
                'severity': 'CRITICAL',
                'description': f'Evil Twin detected! Fake AP mimicking "{ssid}"'
            }
        
        return None
    
    def generate_alert(self, alert_data, ml_prediction=None, ml_confidence=None):
        """Generate and log alert."""
        timestamp = datetime.now()
        
        alert = {
            'timestamp': timestamp.isoformat(),
            'detection_method': 'heuristic',
            **alert_data
        }
        
        # Add ML prediction if available
        if ml_prediction is not None:
            alert['ml_prediction'] = ml_prediction
            alert['ml_confidence'] = ml_confidence
        
        # Log to file
        with open(self.alert_log, 'a') as f:
            f.write(json.dumps(alert) + '\n')
        
        # Update counters
        if alert['type'] == 'rogue_ap':
            self.rogue_ap_count += 1
        elif alert['type'] in ['evil_twin', 'evil_twin_deauth_storm']:
            self.evil_twin_count += 1
        
        self.alerts.append(alert)
        
        # Print alert
        self.print_alert(alert)
    
    def print_alert(self, alert):
        """Print alert to console."""
        severity_colors = {
            'LOW': '🟢',
            'MEDIUM': '🟡',
            'HIGH': '🟠',
            'CRITICAL': '🔴'
        }
        
        icon = severity_colors.get(alert.get('severity', 'MEDIUM'), '⚠️')
        
        print(f"\n{'!'*70}")
        print(f"{icon} ALERT: {alert['type'].upper().replace('_', ' ')}")
        print('!'*70)
        print(f"Time:        {alert['timestamp']}")
        print(f"Severity:    {alert.get('severity', 'UNKNOWN')}")
        print(f"Description: {alert.get('description', 'N/A')}")
        
        if 'ssid' in alert:
            print(f"SSID:        {alert['ssid']}")
        if 'bssid' in alert:
            print(f"BSSID:       {alert['bssid']}")
        if 'fake_bssid' in alert:
            print(f"Fake BSSID:  {alert['fake_bssid']}")
        if 'legitimate_bssids' in alert:
            print(f"Real BSSIDs: {', '.join(alert['legitimate_bssids'])}")
        if 'avg_signal' in alert and alert['avg_signal']:
            print(f"Signal:      {alert['avg_signal']:.1f} dBm")
        
        if 'ml_prediction' in alert:
            attack_names = {4: 'Rogue_AP', 7: 'Evil_Twin'}
            ml_attack = attack_names.get(alert['ml_prediction'], f"Attack_{alert['ml_prediction']}")
            print(f"\nML Detection: {ml_attack} (confidence: {alert['ml_confidence']:.2%})")
        
        print('!'*70)
    
    def packet_handler(self, packet):
        """Handle each captured packet."""
        self.packet_count += 1
        
        # Get ML prediction
        ml_prediction, ml_confidence = self.ml_predict(packet)
        
        # Heuristic analysis
        heuristic_alert = None
        
        # Check for beacon frames (Rogue AP / Evil Twin)
        if packet.haslayer(Dot11Beacon):
            heuristic_alert = self.analyze_beacon(packet)
        
        # Check for deauth frames (Evil Twin indicator)
        elif packet.haslayer(Dot11Deauth):
            heuristic_alert = self.analyze_deauth(packet)
        
        # Generate alert if detected
        if heuristic_alert:
            self.generate_alert(heuristic_alert, ml_prediction, ml_confidence)
        
        # Or if ML detected Rogue AP or Evil Twin
        elif ml_prediction in [4, 7]:  # 4=Rogue_AP, 7=Evil_Twin
            attack_names = {4: 'rogue_ap', 7: 'evil_twin'}
            ml_alert = {
                'type': attack_names[ml_prediction],
                'severity': 'HIGH' if ml_prediction == 7 else 'MEDIUM',
                'description': f'ML model detected {attack_names[ml_prediction]}'
            }
            self.generate_alert(ml_alert, ml_prediction, ml_confidence)
        
        # Print stats every 100 packets
        if self.packet_count % 100 == 0:
            self.print_stats()
    
    def print_stats(self):
        """Print statistics."""
        uptime = (datetime.now() - self.start_time).total_seconds()
        pps = self.packet_count / uptime if uptime > 0 else 0
        
        print(f"\n{'='*70}")
        print(f"Stats: Packets={self.packet_count:,} | Rogue APs={self.rogue_ap_count} | Evil Twins={self.evil_twin_count} | Rate={pps:.1f} pps")
        print('='*70)
        print(f"Detected APs: {len(self.ap_database)}")
        print(f"  Authorized:   {sum(1 for ap in self.ap_database.values() if ap['authorized'])}")
        print(f"  Unauthorized: {sum(1 for ap in self.ap_database.values() if not ap['authorized'])}")
    
    def start(self):
        """Start capturing packets."""
        print(f"\n{'='*70}")
        print(f"STARTING ROGUE AP DETECTION ON {self.interface}")
        print(f"Press Ctrl+C to stop")
        print('='*70 + "\n")
        
        try:
            sniff(
                iface=self.interface,
                prn=self.packet_handler,
                store=False
            )
        except KeyboardInterrupt:
            print("\n\nStopping...")
            self.print_final_stats()
        except Exception as e:
            print(f"\n✗ Error: {str(e)}")
    
    def print_final_stats(self):
        """Print final statistics."""
        uptime = (datetime.now() - self.start_time).total_seconds()
        
        print(f"\n{'='*70}")
        print("FINAL STATISTICS")
        print('='*70)
        print(f"Runtime:         {uptime:.1f} seconds")
        print(f"Total Packets:   {self.packet_count:,}")
        print(f"Rogue APs:       {self.rogue_ap_count}")
        print(f"Evil Twins:      {self.evil_twin_count}")
        
        print(f"\nDetected APs Summary:")
        print(f"  Total APs:     {len(self.ap_database)}")
        print(f"  Authorized:    {sum(1 for ap in self.ap_database.values() if ap['authorized'])}")
        print(f"  Unauthorized:  {sum(1 for ap in self.ap_database.values() if not ap['authorized'])}")
        
        if len(self.ap_database) > 0:
            print(f"\nAll Detected APs:")
            for bssid, info in self.ap_database.items():
                status = "✓ AUTH" if info['authorized'] else "✗ ROGUE"
                print(f"  {status} | {info['ssid']:<20} | {bssid}")
        
        print(f"\n✓ Alerts saved to: {self.alert_log}")
        print('='*70)

def main():
    if len(sys.argv) != 5:
        print("="*70)
        print("Rogue AP and Evil Twin Detection System")
        print("="*70)
        print("\nUsage:")
        print("  sudo python detect_rogue_evil_twin.py <model_path> <scaler_path> <interface> <config_file>")
        print("\nExample:")
        print("  sudo python detect_rogue_evil_twin.py ./models/random_forest_model.pkl ./models/scaler.pkl wlan0mon authorized_aps.json")
        print("\nFeatures:")
        print("  - ML-based detection (Random Forest)")
        print("  - Heuristic detection (beacon analysis)")
        print("  - Evil Twin detection (duplicate SSID)")
        print("  - Deauth storm detection")
        print("  - Authorized AP whitelist")
        print("\nConfig File Format (authorized_aps.json):")
        print('  {')
        print('    "authorized_aps": [')
        print('      {"ssid": "MyNetwork", "bssid": "aa:bb:cc:dd:ee:ff", "description": "Main AP"}')
        print('    ]')
        print('  }')
        print("="*70)
        sys.exit(1)
    
    model_path = sys.argv[1]
    scaler_path = sys.argv[2]
    interface = sys.argv[3]
    config_path = sys.argv[4]
    
    # Verify files
    if not Path(model_path).exists():
        print(f"✗ Error: Model not found: {model_path}")
        sys.exit(1)
    
    if not Path(scaler_path).exists():
        print(f"✗ Error: Scaler not found: {scaler_path}")
        sys.exit(1)
    
    # Start detector
    detector = RogueAPDetector(model_path, scaler_path, interface, config_path)
    detector.start()

if __name__ == "__main__":
    main()
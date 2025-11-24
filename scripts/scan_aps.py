#!/usr/bin/env python3
"""
Scan for all Access Points in range and generate configuration file.
Use this to identify your authorized APs.

Usage:
    sudo python scan_aps.py <interface> <duration_seconds>

Example:
    sudo python scan_aps.py wlan0mon 30
"""

import sys
from pathlib import Path
from datetime import datetime
import json
from collections import defaultdict
import warnings
warnings.filterwarnings('ignore')

try:
    from scapy.all import *
except ImportError:
    print("✗ Error: scapy not installed!")
    sys.exit(1)

class APScanner:
    def __init__(self, interface, duration):
        self.interface = interface
        self.duration = duration
        self.aps = {}
        self.start_time = None
    
    def packet_handler(self, packet):
        """Handle beacon frames."""
        if packet.haslayer(Dot11Beacon):
            try:
                bssid = packet[Dot11].addr3
                ssid = packet[Dot11Elt].info.decode('utf-8', errors='ignore')
                
                # Get channel
                channel = None
                if packet.haslayer(Dot11Elt):
                    elt = packet[Dot11Elt]
                    while elt:
                        if elt.ID == 3:  # DS Parameter Set
                            channel = ord(elt.info)
                            break
                        elt = elt.payload.getlayer(Dot11Elt)
                
                # Get signal strength
                signal = None
                if packet.haslayer(RadioTap) and hasattr(packet[RadioTap], 'dBm_AntSignal'):
                    signal = packet[RadioTap].dBm_AntSignal
                
                # Get capabilities
                cap = packet.sprintf("{Dot11Beacon:%Dot11Beacon.cap%}")
                
                # Check for encryption
                encrypted = 'privacy' in cap.lower()
                
                if bssid not in self.aps:
                    self.aps[bssid] = {
                        'ssid': ssid if ssid else '<Hidden>',
                        'bssid': bssid,
                        'channel': channel,
                        'signal_strengths': [],
                        'encrypted': encrypted,
                        'beacon_count': 0,
                        'first_seen': datetime.now()
                    }
                
                self.aps[bssid]['beacon_count'] += 1
                self.aps[bssid]['last_seen'] = datetime.now()
                
                if signal:
                    self.aps[bssid]['signal_strengths'].append(signal)
            
            except Exception as e:
                pass
    
    def scan(self):
        """Scan for APs."""
        print(f"\n{'='*70}")
        print("SCANNING FOR ACCESS POINTS")
        print('='*70)
        print(f"Interface: {self.interface}")
        print(f"Duration:  {self.duration} seconds")
        print(f"\nScanning... (Press Ctrl+C to stop early)")
        print('='*70 + "\n")
        
        self.start_time = datetime.now()
        
        try:
            sniff(
                iface=self.interface,
                prn=self.packet_handler,
                timeout=self.duration,
                store=False
            )
        except KeyboardInterrupt:
            print("\n\nScan stopped by user...")
        
        print(f"\n✓ Scan complete!")
    
    def print_results(self):
        """Print scan results."""
        print(f"\n{'='*70}")
        print(f"SCAN RESULTS - Found {len(self.aps)} Access Points")
        print('='*70)
        
        if not self.aps:
            print("\n✗ No access points detected!")
            print("  Make sure interface is in monitor mode")
            return
        
        # Sort by signal strength
        sorted_aps = sorted(
            self.aps.values(),
            key=lambda x: sum(x['signal_strengths']) / len(x['signal_strengths']) if x['signal_strengths'] else -100,
            reverse=True
        )
        
        print(f"\n{'#':<4} {'SSID':<25} {'BSSID':<20} {'Ch':<4} {'Signal':<10} {'Enc':<6} {'Beacons':<10}")
        print('-'*90)
        
        for idx, ap in enumerate(sorted_aps, 1):
            ssid = ap['ssid'][:24]
            bssid = ap['bssid']
            channel = ap['channel'] if ap['channel'] else 'N/A'
            
            if ap['signal_strengths']:
                avg_signal = sum(ap['signal_strengths']) / len(ap['signal_strengths'])
                signal_str = f"{avg_signal:.1f} dBm"
            else:
                signal_str = "N/A"
            
            encrypted = "Yes" if ap['encrypted'] else "No"
            beacons = ap['beacon_count']
            
            print(f"{idx:<4} {ssid:<25} {bssid:<20} {channel:<4} {signal_str:<10} {encrypted:<6} {beacons:<10}")
    
    def generate_config(self, output_file='authorized_aps.json'):
        """Generate configuration file."""
        print(f"\n{'='*70}")
        print("GENERATING CONFIGURATION FILE")
        print('='*70)
        
        print("\nSelect authorized APs (enter numbers separated by commas, or 'all' for all):")
        print("Example: 1,3,5  or  all")
        
        choice = input("\nYour selection: ").strip().lower()
        
        selected_aps = []
        
        if choice == 'all':
            selected_aps = list(self.aps.values())
        else:
            try:
                indices = [int(x.strip()) for x in choice.split(',')]
                sorted_aps = sorted(
                    self.aps.values(),
                    key=lambda x: sum(x['signal_strengths']) / len(x['signal_strengths']) if x['signal_strengths'] else -100,
                    reverse=True
                )
                
                for idx in indices:
                    if 1 <= idx <= len(sorted_aps):
                        selected_aps.append(sorted_aps[idx - 1])
            except:
                print("✗ Invalid selection!")
                return
        
        if not selected_aps:
            print("✗ No APs selected!")
            return
        
        # Create config
        config = {
            "authorized_aps": []
        }
        
        for ap in selected_aps:
            config["authorized_aps"].append({
                "ssid": ap['ssid'],
                "bssid": ap['bssid'],
                "description": f"Channel {ap['channel'] if ap['channel'] else 'Unknown'}"
            })
        
        # Save config
        output_path = Path(output_file)
        with open(output_path, 'w') as f:
            json.dump(config, f, indent=2)
        
        print(f"\n✓ Configuration saved to: {output_path}")
        print(f"\nAuthorized APs ({len(selected_aps)}):")
        for ap in selected_aps:
            print(f"  ✓ {ap['ssid']:<25} ({ap['bssid']})")
        
        print(f"\nYou can now use this config file with:")
        print(f"  sudo python detect_rogue_evil_twin.py <model> <scaler> {self.interface} {output_file}")
    
    def run(self):
        """Run complete scan."""
        self.scan()
        self.print_results()
        
        if self.aps:
            print("\n" + "="*70)
            generate = input("Generate authorized APs config file? (y/n): ").strip().lower()
            if generate == 'y':
                self.generate_config()

def main():
    if len(sys.argv) != 3:
        print("="*70)
        print("Access Point Scanner")
        print("="*70)
        print("\nUsage:")
        print("  sudo python scan_aps.py <interface> <duration_seconds>")
        print("\nExample:")
        print("  sudo python scan_aps.py wlan0mon 30")
        print("\nThis will:")
        print("  1. Scan for all APs in range")
        print("  2. Display SSID, BSSID, channel, signal strength")
        print("  3. Generate authorized_aps.json config file")
        print("\nNote:")
        print("  - Interface must be in monitor mode")
        print("  - Requires root/admin privileges")
        print("="*70)
        sys.exit(1)
    
    interface = sys.argv[1]
    duration = int(sys.argv[2])
    
    scanner = APScanner(interface, duration)
    scanner.run()

if __name__ == "__main__":
    main()
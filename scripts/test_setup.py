#!/usr/bin/env python3


import sys
import subprocess
from pathlib import Path

def test_python_version():
    
    print("\n[1/4] Checking Python version...")
    version = sys.version_info
    print(f"      Python {version.major}.{version.minor}.{version.micro}")
    
    if version.major >= 3 and version.minor >= 7:
        print("       Python version is compatible (3.7+)")
        return True
    else:
        print("      ✗ Python 3.7 or higher required")
        return False

def test_tshark():
    
    print("\n[2/4] Checking tshark installation...")
    try:
        result = subprocess.run(
            ['tshark', '--version'],
            capture_output=True,
            text=True,
            timeout=5
        )
        
        if result.returncode == 0:
            
            version_line = result.stdout.split('\n')[0]
            print(f"      {version_line}")
            print("       tshark is installed and working")
            return True
        else:
            print("      ✗ tshark found but not working properly")
            return False
            
    except FileNotFoundError:
        print("      ✗ tshark not found!")
        print("\n      Please install Wireshark/tshark:")
        print("      Ubuntu/Debian: sudo apt-get install tshark")
        print("      macOS: brew install wireshark")
        print("      Windows: Download from https://www.wireshark.org/")
        return False
    except Exception as e:
        print(f"  Error checking tshark: {str(e)}")
        return False

def test_pandas():
    """Check if pandas is installed."""
    print("\n[3/4] Checking pandas installation...")
    try:
        import pandas as pd
        print(f"      pandas version {pd.__version__}")
        print("       pandas is installed")
        return True
    except ImportError:
        print("      pandas not found!")
        print("\n      Please install pandas:")
        print("      pip install pandas")
        return False

def test_scripts():
    """Check if all required scripts are present."""
    print("\n[4/4] Checking for required scripts...")
    
    required_scripts = [
        '0_master_pipeline.py',
        '1_decrypt_pcaps.py',
        '2_extract_features.py',
        '3_apply_filters_and_labels.py',
        '4_dataset_statistics.py',
        '5_combine_datasets.py',
        '6_validate_dataset.py'
    ]
    
    current_dir = Path('.')
    missing_scripts = []
    
    for script in required_scripts:
        if (current_dir / script).exists():
            print(f"       {script}")
        else:
            print(f"      ✗ {script} - MISSING")
            missing_scripts.append(script)
    
    if not missing_scripts:
        print("\n       All required scripts found")
        return True
    else:
        print(f"\n      ✗ Missing {len(missing_scripts)} script(s)")
        return False

def print_summary(results):
    """Print test summary."""
    print("\n" + "="*70)
    print("TEST SUMMARY")
    print("="*70)
    
    all_passed = all(results.values())
    
    for test_name, passed in results.items():
        status = " PASSED" if passed else "✗ FAILED"
        print(f"  {test_name:25s}: {status}")
    
    print("="*70)
    
    if all_passed:
        print("\n ALL TESTS PASSED!")
        print("\nYour environment is ready for AWID3 processing!")
        print("\nNext steps:")
        print("  1. Download AWID3 dataset from https://icsdweb.aegean.gr/awid/awid3")
        print("  2. Organize files:")
        print("     - Put all .pcap files in ./pcaps/")
        print("     - Put key files in ./keys/")
        print("  3. Run: python 0_master_pipeline.py ./pcaps ./keys ./output")
    else:
        print("\n SOME TESTS FAILED!")
        print("\nPlease fix the failed items above before proceeding.")
    
    return all_passed

def main():
    print("="*70)
    print("AWID3 PROCESSING - SETUP VERIFICATION")
    print("="*70)
    print("\nThis script will verify that your environment is ready")
    print("for processing the AWID3 dataset.\n")
    
    # Run all tests
    results = {
        'Python Version': test_python_version(),
        'tshark/Wireshark': test_tshark(),
        'pandas Library': test_pandas(),
        'Required Scripts': test_scripts()
    }
    
    # Print summary
    success = print_summary(results)
    
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()
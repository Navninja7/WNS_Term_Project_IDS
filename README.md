# AWID3 WiFi Intrusion Detection System (IDS)

Complete end-to-end system for processing AWID3 dataset and deploying a production-ready WiFi IDS using Random Forest machine learning.

---

## Table of Contents

1. [Project Overview](#project-overview)
2. [System Requirements](#system-requirements)
3. [Installation](#installation)
4. [Phase 1: Dataset Preparation](#phase-1-dataset-preparation)
5. [Phase 2: ML Model Training](#phase-2-ml-model-training)
6. [Phase 3: Real-time Deployment](#phase-3-real-time-deployment)
7. [Phase 4: Rogue AP Detection](#phase-4-rogue-ap-detection)
8. [Troubleshooting](#troubleshooting)
9. [Project Structure](#project-structure)
10. [Citation](#citation)

---

## Project Overview

This project implements a lightweight WiFi Intrusion Detection System that detects 13 different types of attacks:

| ID | Attack Type | Description |
|----|-------------|-------------|
| 0 | Normal | Benign traffic |
| 1 | Deauth | Deauthentication attack |
| 2 | Disass | Disassociation attack |
| 3 | ReAssoc | Reassociation attack |
| 4 | Rogue_AP | Unauthorized access point |
| 5 | Krack | Key reinstallation attack |
| 6 | Kr00k | Kr00k vulnerability exploit |
| 7 | Evil_Twin | Fake AP mimicking legitimate one |
| 8 | SQL_Injection | SQL injection attack |
| 9 | SSH | SSH brute force |
| 10 | Malware | Malware communication |
| 11 | SSDP | SSDP amplification |
| 12 | Botnet | Botnet C&C traffic |
| 13 | Website_spoofing | Website spoofing attack |

---

## System Requirements

### Hardware Requirements

- **RAM**: 8GB minimum, 16GB+ recommended
- **Storage**: 50GB+ free space
- **CPU**: Multi-core processor (4+ cores recommended)
- **WiFi Adapter**: Monitor mode capable (for real-time detection)
  - Recommended: Alfa AWUS036ACH, TP-Link TL-WN722N v1

### Software Requirements

- **Operating System**: 
  - Linux (Ubuntu 20.04+ recommended)
  - macOS 10.15+
  - Windows 10+ (with limitations)
- **Python**: 3.7 or higher
- **Wireshark/tshark**: 3.2.7 or higher

---

## Installation

### Step 1: Create Virtual Environment

```bash
# Navigate to project directory
cd /path/to/awid3_project

# Create virtual environment
python3 -m venv ids_env

# Activate virtual environment
# On Linux/macOS:
source ids_env/bin/activate

# On Windows:
ids_env\Scripts\activate

# Verify activation (should show virtual env name)
which python
```

### Step 2: Install Python Dependencies

```bash
# Upgrade pip
pip install --upgrade pip

#install from requirements.txt
pip install -r requirements.txt

```

### Step 3: Install System Dependencies

#### On Ubuntu/Debian:

```bash
# Update package list
sudo apt-get update

# Install tshark/Wireshark
sudo apt-get install tshark wireshark

# Install wireless tools
sudo apt-get install aircrack-ng wireless-tools

# Add user to wireshark group (to run without sudo)
sudo usermod -a -G wireshark $USER

# Log out and back in for group changes to take effect
```

#### On macOS:

```bash
# Install Homebrew (if not installed)
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install Wireshark
brew install wireshark

# Install aircrack-ng
brew install aircrack-ng
```

#### On Windows:

1. Download and install Wireshark from: https://www.wireshark.org/download.html
2. Download and install Npcap from: https://npcap.com/
3. Add Wireshark to system PATH

### Step 4: Verify Installation

```bash
# Check tshark
tshark --version

# Check Python packages
python -c "import pandas as pd; print(f'pandas {pd.__version__}')"
python -c "import sklearn; print(f'scikit-learn {sklearn.__version__}')"
python -c "from scapy.all import *; print('scapy OK')"

# Check wireless tools (Linux)
iwconfig
airmon-ng
```

**Expected Output:**
```
TShark (Wireshark) 3.6.2 (Git v3.6.2 packaged as 3.6.2-2)
pandas 1.5.3
scikit-learn 1.2.2
scapy OK
```

---

## Phase 1: Dataset Preparation

### Step 1: Download AWID3 Dataset

```bash
# Create directories
mkdir -p awid3_project/{pcaps,keys,scripts,output}
cd awid3_project

# Download AWID3 from: https://icsdweb.aegean.gr/awid/awid3
# You need:
# - 13 PCAP files (one per attack)
# - 3 key files: 80211_keys_1-5, 80211_keys_6-8, 80211_keys_9-13

# Place files in appropriate directories
mv /path/to/downloaded/*.pcap ./pcaps/
mv /path/to/downloaded/80211_keys_* ./keys/
```

### Step 2: Organize Project Structure

```bash
# Your directory should look like:
awid3_project/
├── ids_env/                    # Virtual environment
├── pcaps/                      # Raw PCAP files
│   ├── 1_Deauth.pcap
│   ├── 2_Disass.pcap
│   └── ... (11 more)
├── keys/                       # Decryption keys
│   ├── 80211_keys_1-5
│   ├── 80211_keys_6-8
│   └── 80211_keys_9-13
├── scripts/                    # Python scripts (place all scripts here)
└── output/                     # Will store processed data
```

### Step 3: Place Scripts

Copy all provided Python scripts to `scripts/` directory:

```bash
cd scripts

# List of scripts you should have:
ls -1
```

**Expected output:**
```
1_decrypt_pcaps.py
2_extract_features.py
3_apply_filters_and_labels.py
4_dataset_statistics.py
5_combine_datasets.py
6_validate_dataset.py
train_ml_model.py
realtime_ids.py
test_model_on_pcap.py
```

### Step 4: Decrypt PCAPs (Optional - Manual if needed)

```bash
# Make sure virtual environment is activated
source ../ids_env/bin/activate

# Decrypt all PCAPs
python 1_decrypt_pcaps.py ../pcaps ../keys ../output/1_decrypted_pcaps

# This will take 30-60 minutes depending on file sizes
```

**Note**: If decryption fails due to Wireshark PMK limits, process in batches:

```bash
# Batch 1: Attacks 1-5
# In Wireshark: Edit → Preferences → Protocols → IEEE 802.11
# Load keys from 80211_keys_1-5
python 1_decrypt_pcaps.py ../pcaps ../keys ../output/batch1

# Batch 2: Attacks 6-8  
# Clear keys in Wireshark, load 80211_keys_6-8
python 1_decrypt_pcaps.py ../pcaps ../keys ../output/batch2

# Batch 3: Attacks 9-13
# Clear keys in Wireshark, load 80211_keys_9-13
python 1_decrypt_pcaps.py ../pcaps ../keys ../output/batch3
```

### Step 5: Extract Features

```bash
# Extract features from decrypted PCAPs
python 2_extract_features.py \
    ../output/1_decrypted_pcaps \
    ../output/2_feature_csvs

# This extracts 100+ features including:
# - Frame metadata
# - Radiotap headers
# - WLAN MAC layer
# - IP/TCP/UDP layers

# Duration: 1-3 hours depending on dataset size
```

**Progress output:**
```
[1/13] Processing 1_Deauth_decrypted.pcap...
✓ Extracted 2,500,000 packets with 156 features
[2/13] Processing 2_Disass_decrypted.pcap...
✓ Extracted 1,800,000 packets with 156 features
...
```

### Step 6: Apply Filters and Labels

```bash
# Apply attack-specific filters and add labels
python 3_apply_filters_and_labels.py \
    ../output/2_feature_csvs \
    ../output/3_labeled_csvs

# This creates labeled datasets:
# - Label 0: Normal traffic
# - Label 1-13: Specific attack types
```

**Output:**
```
Processing: 1_Deauth_decrypted_features.csv
Attack: Deauth (ID: 1)
  Total packets: 2,500,000
  Attack packets: 537,232 (21.49%)
  Normal packets: 1,962,768 (78.51%)
✓ Saved to: 1_Deauth_labeled.csv
```

### Step 7: Validate Datasets

```bash
# Validate data quality
python 6_validate_dataset.py ../output/3_labeled_csvs

# Checks for:
# - Missing labels
# - Data quality issues
# - Class imbalance
# - Duplicate rows
```

**Output:**
```
✓ ALL LABELS PRESENT in both training and testing sets!
✓ No missing values found!
✓ VALIDATION PASSED - Dataset is ready for ML training!
```

---

## Phase 2: ML Model Training

### Step 1: Train Random Forest Model

```bash
# Train model with 70/30 train-test split
python train_ml_model.py \
    ../output/3_labeled_csvs \
    ../models

# This will:
# 1. Load all 13 labeled CSV files
# 2. Combine into single dataset
# 3. Split 70% train / 30% test (stratified)
# 4. Train Random Forest model
# 5. Evaluate on both train and test sets
# 6. Generate confusion matrices
# 7. Save trained model

# Duration: 30 minutes - 2 hours
```

**Training output:**
```
======================================================================
STEP 1: LOADING DATASETS
======================================================================
Found 13 labeled CSV files
✓ Combined Dataset:
  Total samples: 25,000,000
  Total features: 156

======================================================================
STEP 3: SPLITTING DATA (70% TRAIN / 30% TEST)
======================================================================
Training set: 17,500,000 samples (70%)
Testing set:  7,500,000 samples (30%)

✓ ALL LABELS PRESENT in both training and testing sets!

======================================================================
STEP 5: TRAINING RANDOM FOREST MODEL
======================================================================
Model Configuration (Regularized):
  n_estimators:      100
  max_depth:         12
  min_samples_split: 20
  min_samples_leaf:  10

Training...
✓ Training completed in 1847.32 seconds

======================================================================
STEP 6: EVALUATING MODEL
======================================================================

TRAINING SET METRICS
--------------------
Accuracy:  0.9612
Precision: 0.9608
Recall:    0.9612
F1-Score:  0.9609

TESTING SET METRICS
-------------------
Accuracy:  0.9534
Precision: 0.9528
Recall:    0.9534
F1-Score:  0.9530

OVERFITTING ANALYSIS
--------------------
Train-Test Gap: 0.0078
✓ EXCELLENT: No overfitting detected

======================================================================
✓ TRAINING COMPLETE!
======================================================================
```

### Step 2: Review Training Results

```bash
# Check output files
ls -lh ../models/

# You should see:
# - random_forest_model.pkl (trained model)
# - scaler.pkl (feature scaler)
# - evaluation_results.json (metrics)
# - confusion_matrices_train_test.png (visualizations)
# - metrics_comparison_train_test.png (performance comparison)

# View results
cat ../models/evaluation_results.json | python -m json.tool
```

### Step 3: Analyze Performance

Open the generated plots:

**confusion_matrices_train_test.png**:
- Shows confusion matrices for both train and test sets
- Helps identify which attacks are confused with each other

**metrics_comparison_train_test.png**:
- Compares precision, recall, and F1-score
- Shows performance per attack type

---

## Phase 3: Real-time Deployment

### Step 1: Setup WiFi Adapter for Monitoring

#### Check WiFi Adapter

```bash
# List network interfaces
iwconfig

# Check if adapter supports monitor mode
iw list | grep -A 10 "Supported interface modes"

# You should see:
#  * monitor
```

#### Enable Monitor Mode

```bash
# Kill interfering processes
sudo airmon-ng check kill

# Enable monitor mode on wlan0
sudo airmon-ng start wlan0

# This creates wlan0mon interface

# Verify
iwconfig wlan0mon
# Should show: Mode:Monitor
```

### Step 2: Test Model on Saved PCAP (Optional)

```bash
# Test model before live deployment
python test_pcap_rf.py \
    ../models/random_forest_model.pkl \
    ../models/scaler.pkl \
    ../pcaps/1_Deauth.pcap

# Output:
# - Detection report (JSON)
# - Attack distribution plot
# - Timeline visualization
# - Confidence distribution
```

**Output:**
```
Processing: 1_Deauth.pcap
✓ Loaded 500,000 packets

Detection Summary:
  Total Packets:  500,000
  Normal Traffic: 390,000 (78.00%)
  Attack Traffic: 110,000 (22.00%)

Attack Type Distribution:
  Deauth              :  110,000 ( 22.00%)

✓ Results saved to: test_results/
```

### Step 3: Start Real-time IDS

```bash
# Start IDS with trained model
sudo python realtime_ids_rf.py \
    ../models/random_forest_model.pkl \
    ../models/scaler.pkl \
    wlan0mon

# IDS is now running!
# Press Ctrl+C to stop
```

**Live output:**
```
======================================================================
REAL-TIME IDS INITIALIZED
======================================================================
Interface:  wlan0mon
Model:      Random Forest
Alert Log:  alerts.log
======================================================================

STARTING CAPTURE ON wlan0mon
Press Ctrl+C to stop
======================================================================

Stats: Packets=5,000 | Alerts=42 | Rate=250.5 pps
======================================================================
Attack Distribution:
  Deauth              :    30 ( 71.4%)
  Disass              :    12 ( 28.6%)

!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
🚨 ALERT DETECTED!
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
Time:       2024-01-15 10:30:45
Attack:     Deauth (ID: 1)
Confidence: 96.50%
Source MAC: aa:bb:cc:dd:ee:ff
Dest MAC:   11:22:33:44:55:66
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
```

### Step 4: Monitor Alerts

Open a new terminal:

```bash
# Activate virtual environment
source ids_env/bin/activate
cd scripts

# Watch alerts in real-time
tail -f alerts.log

# Or parse JSON alerts
tail -f alerts.log | python -m json.tool

# Count alerts by type
cat alerts.log | grep -o '"attack_type":"[^"]*"' | sort | uniq -c

# Filter high-confidence alerts
cat alerts.log | grep -E '"confidence":(0\.[9][5-9]|1\.0)'
```

---

## 🔍 Phase 4: Rogue AP Detection

### Step 1: Scan for Authorized APs

```bash
# Scan for all APs in range (60 seconds)
sudo python scan_aps.py wlan0mon 60

# This will discover all nearby APs
```

**Output:**
```
======================================================================
SCAN RESULTS - Found 15 Access Points
======================================================================

#    SSID                      BSSID                Ch   Signal     Enc    Beacons   
------------------------------------------------------------------------------------------
1    CompanyWiFi-Main          aa:bb:cc:dd:ee:ff    6    -45.2 dBm  Yes    120       
2    CompanyWiFi-Guest         aa:bb:cc:dd:ee:01    11   -48.5 dBm  Yes    115       
3    Neighbor_Network          11:22:33:44:55:66    1    -72.1 dBm  Yes    95        
4    FreeWiFi                  99:88:77:66:55:44    6    -65.3 dBm  No     85        

Select authorized APs (enter numbers separated by commas):
Your selection: 1,2

✓ Configuration saved to: authorized_aps.json
```

### Step 2: Review Configuration

```bash
# Check generated config
cat authorized_aps.json
```

**Example config:**
```json
{
  "authorized_aps": [
    {
      "ssid": "CompanyWiFi-Main",
      "bssid": "aa:bb:cc:dd:ee:ff",
      "description": "Channel 6"
    },
    {
      "ssid": "CompanyWiFi-Guest",
      "bssid": "aa:bb:cc:dd:ee:01",
      "description": "Channel 11"
    }
  ]
}
```

### Step 3: Start Rogue AP Detection

```bash
# Start enhanced detector
sudo python detect_rogue_evil_twin.py \
    ../models/random_forest_model.pkl \
    ../models/scaler.pkl \
    wlan0mon \
    authorized_aps.json

# Detects:
# - Rogue APs (unauthorized)
# - Evil Twins (duplicate SSID)
# - Deauth storms
```

**Alert example:**
```
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
🔴 ALERT: EVIL TWIN
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
Time:        2024-01-15T10:35:12
Severity:    CRITICAL
Description: Evil Twin detected! Fake AP mimicking "CompanyWiFi-Main"
SSID:        CompanyWiFi-Main
Fake BSSID:  11:22:33:44:55:66
Real BSSIDs: aa:bb:cc:dd:ee:ff
Signal:      -48.1 dBm

ML Detection: Evil_Twin (confidence: 96.20%)
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
```

---

## 🔧 Troubleshooting

### Issue 1: Virtual Environment Not Activating

**Problem**: `source ids_env/bin/activate` doesn't work

**Solution**:
```bash
# Recreate virtual environment
rm -rf ids_env
python3 -m venv ids_env

# On Windows use:
python -m venv ids_env
ids_env\Scripts\activate.bat
```

### Issue 2: Module Not Found Errors

**Problem**: `ModuleNotFoundError: No module named 'pandas'`

**Solution**:
```bash
# Ensure virtual environment is activated
which python  # Should show path to ids_env

# Reinstall packages
pip install pandas numpy scikit-learn matplotlib seaborn scapy

# Verify
python -c "import pandas; print('OK')"
```

### Issue 3: tshark Command Not Found

**Problem**: `tshark: command not found`

**Solution**:
```bash
# Ubuntu/Debian
sudo apt-get install tshark wireshark

# macOS
brew install wireshark

# Verify installation
tshark --version
```

### Issue 4: Permission Denied for Packet Capture

**Problem**: `Permission denied` when running real-time IDS

**Solution**:
```bash
# Option 1: Run with sudo
sudo python realtime_ids_rf.py ...

# Option 2: Add user to groups (Linux)
sudo usermod -a -G wireshark $USER
sudo usermod -a -G netdev $USER
# Log out and back in

# Option 3: Set capabilities (Linux)
sudo setcap cap_net_raw,cap_net_admin=eip $(which python3)
```

### Issue 5: Monitor Mode Not Working

**Problem**: Cannot enable monitor mode

**Solution**:
```bash
# Check if adapter supports monitor mode
iw list | grep -A 10 "Supported interface modes"

# Kill interfering processes
sudo airmon-ng check kill

# Try alternative method
sudo ip link set wlan0 down
sudo iw wlan0 set monitor control
sudo ip link set wlan0 up

# Verify
iwconfig wlan0
```

### Issue 6: Out of Memory During Training

**Problem**: System runs out of memory

**Solution**:
```bash
# Option 1: Use sampling
# Edit train_ml_model.py, add after loading:
df = df.sample(n=1000000, random_state=42)  # Use 1M samples

# Option 2: Process one file at a time
# Option 3: Increase swap space
sudo fallocate -l 8G /swapfile
sudo chmod 600 /swapfile
sudo mkswap /swapfile
sudo swapon /swapfile
```

### Issue 7: Feature Extraction Fails

**Problem**: Invalid field names in tshark

**Solution**:
```bash
# The script has automatic field validation
# If still failing, check tshark version
tshark --version

# Update to latest version
# Ubuntu:
sudo apt-get update
sudo apt-get install --only-upgrade wireshark tshark

# macOS:
brew upgrade wireshark
```

### Issue 8: No Attacks Detected in Real-time

**Problem**: IDS running but no alerts

**Possible causes**:
- Monitor mode on wrong channel
- No actual attacks occurring
- Model not detecting properly

**Solution**:
```bash
# Check current channel
iwconfig wlan0mon

# Channel hop to scan all channels
# (Add to realtime_ids_rf.py or use airodump-ng)

# Generate test traffic (in lab environment only!)
sudo aireplay-ng --deauth 10 -a AA:BB:CC:DD:EE:FF wlan0mon
```

---

## Project Structure

```
awid3_project/
│
├── ids_env/                          # Virtual environment
│   ├── bin/
│   ├── lib/
│   └── ...
│
├── pcaps/                            # Raw PCAP files (input)
│   ├── 1_Deauth.pcap
│   ├── 2_Disass.pcap
│   └── ... (11 more)
│
├── keys/                             # Decryption keys (input)
│   ├── 80211_keys_1-5
│   ├── 80211_keys_6-8
│   └── 80211_keys_9-13
│
├── scripts/                          # Python scripts
│   ├── 1_decrypt_pcaps.py
│   ├── 2_extract_features.py
│   ├── 3_apply_filters_and_labels.py
│   ├── 4_dataset_statistics.py
│   ├── 5_combine_datasets.py
│   ├── 6_validate_dataset.py
│   ├── train_ml_model.py             Main training script
│   ├── realtime_ids_rf.py            Real-time detection
│   ├── test_pcap_rf.py
│   ├── detect_rogue_evil_twin.py     Rogue AP detection
│   └── scan_aps.py
│
├── output/                           # Processed data
│   ├── 1_decrypted_pcaps/           # Decrypted PCAPs
│   ├── 2_feature_csvs/              # Feature CSVs
│   └── 3_labeled_csvs/              # Labeled datasets 
│
├── models/                           # Trained models 
│   ├── random_forest_model.pkl      # Main model
│   ├── scaler.pkl                   # Feature scaler
│   ├── evaluation_results.json
│   ├── confusion_matrices_train_test.png
│   └── metrics_comparison_train_test.png
│
├── alerts.log                        # Real-time alerts
├── rogue_ap_alerts.log              # Rogue AP alerts
├── authorized_aps.json              # AP whitelist
└── README.md                        # This file
```

---

## Usage Examples

### Example 1: Complete Workflow

```bash
# 1. Setup
python3 -m venv ids_env
source ids_env/bin/activate
pip install pandas numpy scikit-learn matplotlib seaborn scapy

# 2. Process dataset
cd scripts
python 2_extract_features.py ../output/1_decrypted_pcaps ../output/2_feature_csvs
python 3_apply_filters_and_labels.py ../output/2_feature_csvs ../output/3_labeled_csvs

# 3. Train model
python train_ml_model.py ../output/3_labeled_csvs ../models

# 4. Deploy
sudo airmon-ng start wlan0
sudo python realtime_ids_rf.py ../models/random_forest_model.pkl ../models/scaler.pkl wlan0mon
```

### Example 2: Test on PCAP File

```bash
# Test model on specific attack
python test_pcap_rf.py \
    ../models/random_forest_model.pkl \
    ../models/scaler.pkl \
    ../pcaps/7_Evil_Twin.pcap

# Check results
ls test_results/
# - 7_Evil_Twin_report.json
# - 7_Evil_Twin_distribution.png
# - 7_Evil_Twin_timeline.png
```

### Example 3: Rogue AP Detection

```bash
# Scan environment
sudo python scan_aps.py wlan0mon 60

# Select authorized APs
# 1, 2, 3

# Start detection
sudo python detect_rogue_evil_twin.py \
    ../models/random_forest_model.pkl \
    ../models/scaler.pkl \
    wlan0mon \
    authorized_aps.json
```

---

## Expected Performance

### Training Metrics

| Metric | Training Set | Testing Set |
|--------|--------------|-------------|
| **Accuracy** | 0.9612 | 0.9534 |
| **Precision** | 0.9608 | 0.9528 |
| **Recall** | 0.9612 | 0.9534 |
| **F1-Score** | 0.9609 | 0.9530 |

### Real-time Performance

- **Processing Rate**: 100-500 packets/second
- **Detection Latency**: < 100ms per packet
- **Memory Usage**: 200-500 MB
- **CPU Usage**: 20-40% (single core)

---

## Citation

If you use this system in your research, please cite:

```bibtex
@article{chatzoglou2021awid3,
  title={Empirical Evaluation of Attacks Against IEEE 802.11 Enterprise Networks: The AWID3 Dataset},
  author={Chatzoglou, Eustathios and Kambourakis, Georgios and Kolias, Constantinos},
  journal={IEEE Access},
  volume={9},
  pages={34188--34205},
  year={2021},
  publisher={IEEE}
}
```

---

## Support

### Common Issues

- **Script errors**: Check virtual environment is activated
- **Permission errors**: Use sudo for packet capture
- **Memory errors**: Reduce dataset size or increase RAM
- **No detections**: Verify monitor mode and channel

### Resources

- **AWID3 Dataset**: https://icsdweb.aegean.gr/awid/awid3
- **Wireshark Docs**: https://www.wireshark.org/docs/
- **Scapy Tutorial**: https://scapy.readthedocs.io/
- **Scikit-learn**: https://scikit-learn.org/

---

## Quick Reference

### Activate Environment
```bash
source ids_env/bin/activate  # Linux/macOS
ids_env\Scripts\activate     # Windows
```

### Process Dataset
```bash
python 2_extract_features.py ../output/1_decrypted_pcaps ../output/2_feature_csvs
python 3_apply_filters_and_labels.py ../output/2_feature_csvs ../output/3_labeled_csvs
```

### Train Model
```bash
python train_ml_model.py ../output/3_labeled_csvs ../models
```

### Deploy IDS
```bash
sudo airmon-ng start wlan0
sudo python realtime_ids_rf.py ../models/random_forest_model.pkl ../models/scaler.pkl wlan0mon
```

### Stop IDS
```bash
# Press Ctrl+C in IDS terminal
sudo airmon-ng stop wlan0mon
```

---

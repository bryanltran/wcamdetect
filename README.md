# WCamDetect

WCamDetect is a wireless-camera traffic identification system that collects packets using tcpdump, extracts header-level features, and trains classical machine learning models to distinguish camera traffic from non-camera wireless devices. The system includes a full data-collection pipeline, automated feature extraction, model training scripts, statistical plots, and a graphical interface for classifying new packet captures.

---

## Demo Video

[![Watch the video](https://img.youtube.com/vi/uJpI7AqZzJM/maxresdefault.jpg)](https://www.youtube.com/watch?v=uJpI7AqZzJM)


The video covers:  
- Setup  
- Editing `capture.sh`  
- Capturing pcaps  
- Running `parse.py`  
- Running `train.py`  
- Viewing plots  
- Using the GUI  

---

## Project Overview

WCamDetect provides an end-to-end workflow:

1. **Data Collection** – Capture raw pcap files using tcpdump.  
2. **Feature Extraction** – Parse pcaps to extract statistical, timing, and structural features.  
3. **Model Training** – Train Random Forest, SVM, and KNN models.  
4. **Evaluation** – Automatically generate confusion matrices and performance plots.  
5. **GUI Interface** – Load any pcap file and classify whether it contains camera traffic.

The system uses only metadata (packet headers, lengths, timing patterns) and never inspects encrypted payloads.

---

## Repository Structure

```
wcamdetect/  
├── data/  
│   ├── raw/         # raw packet captures  
│   ├── processed/   # extracted feature JSON files  
│   ├── models/      # trained ML model files  
│   └── plots/       # evaluation plots  
├── capture.sh       # tcpdump capture script  
├── parse.py         # feature extraction  
├── train.py         # model training  
└── interface/       # GUI application
```

---

## Setup Instructions

1. Be in a Linux Environment.  
2. Clone the repository:
   ```bash
   git clone <repository-link>
   cd wcamdetect
   ```
3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
4. Create directories:
   ```
   data/  
   └── raw/
   ```

---

## Data Collection

Before running `capture.sh`, edit these variables:

```bash
WIFI_INTERFACE="xxxxxx"  
CAPTURE_DIR="data/raw/"  
BLINK_SYNC="xx:xx:xx:xx:xx:xx"
```

- `WIFI_INTERFACE` should match your wireless interface.  
- `CAPTURE_DIR` is where pcaps are saved.  
- `BLINK_SYNC` must be the MAC address of the device being monitored.

Find interfaces using:
```bash
ip link
# or
iw dev
# or
arp-scan
```

Install tcpdump:
```bash
sudo apt install tcpdump
```

Make the script executable:
```bash
chmod +x capture.sh
```

Running it previews packets; press Enter to begin capture.

---

## Feature Extraction

Run:
```bash
python scripts/parse.py
```

Outputs features to:
```
data/processed/features.json
```

---

## Model Training

Run:
```bash
python scripts/train.py
```

Produces:
- `data/models/*.pkl`  
- `data/plots/*.png`

---

## GUI Classification Tool

Run:
```bash
python interface/gui.py
```

Steps:  
1. Load a pcap file  
2. Click "Classify Device"  
3. Receive classification + confidence score

---

## Notes

- More training data improves accuracy.  
- Only metadata is analyzed; payloads remain untouched.  
- Even small datasets reveal differences between camera and non-camera traffic.

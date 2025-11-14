
import json
import numpy as np
from scapy.all import rdpcap, Dot11
from collections import Counter
import glob
import sys
import os
from pathlib import Path

class PCAPFeatureExtractor:
    """Extract ML features from PCAP files"""
    
    def __init__(self, window_size=50):
        self.window_size = window_size
        
    def extract_pld_features(self, packet_lengths):
        """Packet Length Distribution features"""
        if len(packet_lengths) == 0:
            return {}
        
        features = {
            'pld_mean': float(np.mean(packet_lengths)),
            'pld_std': float(np.std(packet_lengths)),
            'pld_min': int(np.min(packet_lengths)),
            'pld_max': int(np.max(packet_lengths)),
            'pld_median': float(np.median(packet_lengths)),
            'pld_range': int(np.max(packet_lengths) - np.min(packet_lengths)),
        }
        
        # Histogram for staircase pattern
        hist, _ = np.histogram(packet_lengths, bins=10)
        for i, count in enumerate(hist):
            features[f'pld_hist_{i}'] = float(count / len(packet_lengths))
        
        # Alternating pattern detection
        if len(packet_lengths) > 1:
            diffs = np.diff(packet_lengths)
            sign_changes = np.abs(np.diff(np.sign(diffs)))
            features['pld_alternation_score'] = float(np.sum(sign_changes) / len(packet_lengths))
        else:
            features['pld_alternation_score'] = 0.0
        
        # Bimodal distribution
        threshold = np.median(packet_lengths)
        small_packets = np.sum(packet_lengths < threshold)
        features['pld_small_packet_ratio'] = float(small_packets / len(packet_lengths))
        
        return features
    
    def extract_pld_stability(self, packet_lengths):
        """PLD consistency over time"""
        if len(packet_lengths) < self.window_size:
            return {'pld_stability_cv': 0.0}
        
        windows = [packet_lengths[i:i+self.window_size] 
                   for i in range(0, len(packet_lengths)-self.window_size, self.window_size//2)]
        
        if len(windows) < 2:
            return {'pld_stability_cv': 0.0}
        
        window_means = [np.mean(w) for w in windows]
        window_stds = [np.std(w) for w in windows]
        
        mean_cv = np.std(window_means) / (np.mean(window_means) + 1e-6)
        std_cv = np.std(window_stds) / (np.mean(window_stds) + 1e-6)
        
        return {
            'pld_stability_cv': float(mean_cv),
            'pld_std_stability': float(std_cv),
            'pld_window_variance': float(np.var(window_means))
        }
    
    def extract_bandwidth_features(self, packet_lengths, timestamps):
        """Bandwidth stability"""
        if len(timestamps) < self.window_size:
            return {'bandwidth_cv': 0.0}
        
        bitrates = []
        for i in range(0, len(timestamps)-self.window_size, self.window_size//2):
            window_times = timestamps[i:i+self.window_size]
            window_bytes = packet_lengths[i:i+self.window_size]
            
            time_diff = window_times[-1] - window_times[0]
            if time_diff > 0:
                bitrate = (sum(window_bytes) * 8) / time_diff
                bitrates.append(bitrate)
        
        if len(bitrates) == 0:
            return {'bandwidth_cv': 0.0}
        
        bandwidth_cv = np.std(bitrates) / (np.mean(bitrates) + 1e-6)
        
        return {
            'bandwidth_mean': float(np.mean(bitrates)),
            'bandwidth_std': float(np.std(bitrates)),
            'bandwidth_cv': float(bandwidth_cv),
            'bandwidth_range': float(np.max(bitrates) - np.min(bitrates))
        }
    
    def extract_duration_features(self, durations):
        """Duration field from MAC headers"""
        if len(durations) == 0:
            return {'duration_mode': 0, 'duration_entropy': 0.0}
        
        counter = Counter(durations)
        mode = counter.most_common(1)[0][0] if counter else 0
        
        probs = np.array(list(counter.values())) / len(durations)
        entropy = -np.sum(probs * np.log2(probs + 1e-10))
        
        return {
            'duration_mean': float(np.mean(durations)),
            'duration_std': float(np.std(durations)),
            'duration_mode': int(mode),
            'duration_unique_count': len(set(durations)),
            'duration_entropy': float(entropy),
            'duration_mode_freq': float(counter[mode] / len(durations))
        }
    
    def extract_features(self, pcap_file):
        """Extract all features from one PCAP file"""
        try:
            packets = rdpcap(pcap_file)
        except Exception as e:
            print(f"Error reading {pcap_file}: {e}")
            return None
        
        packet_lengths = []
        timestamps = []
        durations = []
        
        for pkt in packets:
            packet_lengths.append(len(pkt))
            timestamps.append(float(pkt.time))
            
            if pkt.haslayer(Dot11):
                durations.append(pkt[Dot11].ID)
        
        features = {}
        features.update(self.extract_pld_features(packet_lengths))
        features.update(self.extract_pld_stability(packet_lengths))
        features.update(self.extract_bandwidth_features(packet_lengths, timestamps))
        features.update(self.extract_duration_features(durations))
        features['packet_count'] = len(packet_lengths)
        
        return features

def parse_pcaps():
    """Parse all PCAPs from data/raw/ and save to data/processed/features.json"""
    
    # Setup paths (relative to project root)
    project_root = Path(__file__).parent.parent
    raw_dir = project_root / "data" / "raw"
    processed_dir = project_root / "data" / "processed"
    output_json = processed_dir / "features.json"
    
    # Create directories if they don't exist
    raw_dir.mkdir(parents=True, exist_ok=True)
    processed_dir.mkdir(parents=True, exist_ok=True)
    
    print(f"Looking for PCAP files in: {raw_dir}")
    
    extractor = PCAPFeatureExtractor()
    
    camera_flows = list(raw_dir.glob("camera_*.pcap"))
    non_camera_flows = list(raw_dir.glob("non-camera_*.pcap"))
    
    print(f"Found {len(camera_flows)} camera flows")
    print(f"Found {len(non_camera_flows)} non-camera flows")
    
    if len(camera_flows) == 0 and len(non_camera_flows) == 0:
        print(f"\n  No PCAP files found in {raw_dir}")
        print("Please add PCAP files with naming:")
        print("  - camera_*.pcap for camera flows")
        print("  - non-camera_*.pcap for non-camera flows")
        return
    
    dataset = []
    
    # Process camera flows
    for pcap_file in camera_flows:
        print(f"Processing {pcap_file.name}...")
        features = extractor.extract_features(str(pcap_file))
        if features:
            features['label'] = 'camera'
            features['filename'] = pcap_file.name
            dataset.append(features)
    
    # Process non-camera flows
    for pcap_file in non_camera_flows:
        print(f"Processing {pcap_file.name}...")
        features = extractor.extract_features(str(pcap_file))
        if features:
            features['label'] = 'non-camera'
            features['filename'] = pcap_file.name
            dataset.append(features)
    
    # Save to JSON
    with open(output_json, 'w') as f:
        json.dump(dataset, f, indent=2)
    
    print(f"\n✓ Saved {len(dataset)} feature vectors to {output_json}")
    print(f"  Camera flows: {len(camera_flows)}")
    print(f"  Non-camera flows: {len(non_camera_flows)}")

def main():
    print("Running PCAP extraction")
    parse_pcaps()

if __name__ == "__main__":
    main()

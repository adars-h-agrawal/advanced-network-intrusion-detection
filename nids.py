from scapy.all import sniff, IP, TCP, UDP, ICMP
import pandas as pd
from collections import Counter, defaultdict
import time
from datetime import datetime
import sys
import io
import os

# Fix Windows console encoding issues
if sys.platform == 'win32':
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

print("Starting Enhanced Network Intrusion Detection System...\n")

# Configuration
HISTORICAL_DATA_FILE = "data/historical_data.csv"
SESSION_DATA_FILE = "data/captured_data.csv"
MIN_TRAINING_SAMPLES = 100  # Minimum samples before training ML model

captured = []
ip_counter = Counter()
port_counter = defaultdict(Counter)
protocol_counter = Counter()
connection_tracker = {}

def load_historical_data():
    """Load previously captured data"""
    if os.path.exists(HISTORICAL_DATA_FILE):
        try:
            df = pd.read_csv(HISTORICAL_DATA_FILE)
            print(f"[INFO] Loaded {len(df)} historical packets from previous sessions")
            return df
        except Exception as e:
            print(f"[WARNING] Could not load historical data: {e}")
            return pd.DataFrame()
    else:
        print("[INFO] No historical data found. Starting fresh.")
        return pd.DataFrame()

def extract_features(packet):
    """Extract comprehensive features from packet"""
    features = {
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'src_ip': None,
        'dst_ip': None,
        'src_port': None,
        'dst_port': None,
        'protocol': None,
        'length': len(packet),
        'ttl': None,
        'flags': None,
        'payload_size': 0
    }
    
    if packet.haslayer(IP):
        features['src_ip'] = packet[IP].src
        features['dst_ip'] = packet[IP].dst
        features['ttl'] = packet[IP].ttl
        features['protocol'] = packet[IP].proto
        
        # Track protocol statistics
        protocol_counter[features['protocol']] += 1
        
        # TCP specific features
        if packet.haslayer(TCP):
            features['src_port'] = packet[TCP].sport
            features['dst_port'] = packet[TCP].dport
            features['flags'] = packet[TCP].flags
            features['payload_size'] = len(packet[TCP].payload)
            
        # UDP specific features
        elif packet.haslayer(UDP):
            features['src_port'] = packet[UDP].sport
            features['dst_port'] = packet[UDP].dport
            features['payload_size'] = len(packet[UDP].payload)
    
    return features

def detect_anomalies(features):
    """Enhanced rule-based anomaly detection"""
    anomaly_score = 0
    reasons = []
    
    src_ip = features['src_ip']
    dst_port = features['dst_port']
    
    if not src_ip:
        return 0, ["No IP layer"], "Normal"
    
    # Count IP appearances
    ip_counter[src_ip] += 1
    
    # Rule 1: Unusual packet size
    if features['length'] > 800:
        anomaly_score += 0.3
        reasons.append("Large packet size")
    
    # Rule 2: High frequency from same IP (possible DoS)
    if ip_counter[src_ip] > 5:
        anomaly_score += 0.4
        reasons.append(f"High frequency from {src_ip}")
    
    # Rule 3: Suspicious ports
    suspicious_ports = {23, 445, 3389, 1433, 3306}  # Telnet, SMB, RDP, SQL
    if dst_port in suspicious_ports:
        anomaly_score += 0.3
        reasons.append(f"Suspicious port {dst_port}")
    
    # Rule 4: Unusual TTL values
    if features['ttl'] and (features['ttl'] < 30 or features['ttl'] > 128):
        anomaly_score += 0.2
        reasons.append("Unusual TTL")
    
    # Rule 5: SYN flood detection (TCP SYN flag without ACK)
    if features['flags'] and 'S' in str(features['flags']) and 'A' not in str(features['flags']):
        port_counter[src_ip][dst_port] += 1
        if port_counter[src_ip][dst_port] > 3:
            anomaly_score += 0.5
            reasons.append("Possible SYN flood")
    
    # Determine status
    status = "Suspicious" if anomaly_score >= 0.5 else "Normal"
    
    return round(anomaly_score, 3), reasons, status

def analyze_packet(packet):
    """Main packet analysis function"""
    features = extract_features(packet)
    
    if features['src_ip']:
        anomaly_score, reasons, status = detect_anomalies(features)
        
        # Prepare data for CSV
        packet_data = {
            'Timestamp': features['timestamp'],
            'Source_IP': features['src_ip'],
            'Destination_IP': features['dst_ip'],
            'Source_Port': features['src_port'],
            'Destination_Port': features['dst_port'],
            'Protocol': features['protocol'],
            'Length': features['length'],
            'TTL': features['ttl'],
            'Payload_Size': features['payload_size'],
            'Anomaly_Score': anomaly_score,
            'Status': status,
            'Reason': ', '.join(reasons) if reasons else 'Normal traffic'
        }
        
        captured.append(packet_data)
        
        # Console output (ASCII only)
        status_icon = "[!]" if status == "Suspicious" else "[+]"
        print(f"{status_icon} {features['src_ip']:18} -> {features['dst_ip']:18} | "
              f"Port: {str(features['dst_port'] or 'N/A'):5} | Size: {features['length']:5} | "
              f"Score: {anomaly_score:.2f} | {status}")

def save_data(append_to_history=True):
    """Save captured data and append to historical dataset"""
    if not captured:
        print("\n[WARNING] No packets captured.")
        return

    # Save current session data
    current_df = pd.DataFrame(captured)
    os.makedirs("data", exist_ok=True)
    current_df.to_csv(SESSION_DATA_FILE, index=False)
    print(f"[SAVE] Current session data saved to '{SESSION_DATA_FILE}'")

    # Append to historical data
    if append_to_history:
        header = not os.path.exists(HISTORICAL_DATA_FILE)
        current_df.to_csv(HISTORICAL_DATA_FILE, mode='a', header=header, index=False)
        print(f"[APPEND] {len(current_df)} packets added to historical dataset")

    '''
    # Optional: Keep file manageable
        historical_df = pd.read_csv(HISTORICAL_DATA_FILE)
        if len(historical_df) > 10000:
            historical_df = historical_df.tail(10000)
            historical_df.to_csv(HISTORICAL_DATA_FILE, index=False)
            print("[INFO] Trimmed historical dataset to last 10,000 packets")
    '''

def main():
    print("="*100)
    print("NETWORK INTRUSION DETECTION SYSTEM - CONTINUOUS LEARNING MODE")
    print("="*100)
    
    # Load historical data
    historical_df = load_historical_data()
    
    # Get packet count from user
    try:
        packet_count = int(input("\nEnter number of packets to capture (default 50): ") or "50")
    except ValueError:
        packet_count = 50
    
    append_choice = input("Append to historical data? (y/n, default y): ").lower()
    append_to_history = append_choice != 'n'
    
    print(f"\n[START] Capturing {packet_count} packets... Generate some network activity.")
    print("-" * 100)
    
    try:
        sniff(prn=analyze_packet, count=packet_count, timeout=120)
    except KeyboardInterrupt:
        print("\n\n[INTERRUPT] Capture interrupted by user.")
    except Exception as e:
        print(f"\n[ERROR] Error during packet capture: {e}")
        print("Make sure you're running with administrator/root privileges.")
    
    if not captured:
        print("\n[WARNING] No packets captured. Check your network interface permissions.")
        print("On Windows, run as Administrator. On Linux/Mac, use sudo.")
        return
    
    # Save data
    save_data(append_to_history)
    
    # Statistics
    current_df = pd.DataFrame(captured)
    print(f"\n[STATS] Session Summary:")
    print(f"  - Total packets: {len(captured)}")
    print(f"  - Normal: {len(current_df[current_df['Status'] == 'Normal'])}")
    print(f"  - Suspicious: {len(current_df[current_df['Status'] == 'Suspicious'])}")
    
    # Show protocol distribution
    print(f"\n[PROTOCOL] Distribution:")
    for proto, count in protocol_counter.most_common():
        proto_name = {6: 'TCP', 17: 'UDP', 1: 'ICMP'}.get(proto, f'Protocol {proto}')
        print(f"  {proto_name}: {count}")
    
    # Check if enough data for ML
    if append_to_history:
        total_samples = len(load_historical_data())
        print(f"\n[ML] Total historical samples: {total_samples}")
        if total_samples < MIN_TRAINING_SAMPLES:
            print(f"[INFO] Need {MIN_TRAINING_SAMPLES - total_samples} more samples for reliable ML training")
            print(f"[TIP] Run this script multiple times to build a larger dataset")
        else:
            print(f"[SUCCESS] Dataset is large enough for ML training!")
    
    print("\n[DONE] Run the dashboard: streamlit run dashboard.py")
    print("="*100)

if __name__ == "__main__":
    main()

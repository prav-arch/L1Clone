#!/usr/bin/env python3
"""
Unified L1 Anomaly Detection System
Analyzes both PCAP files and HDF5-converted text files for comprehensive L1 troubleshooting
Detects DU-RU communication failures and UE Attach/Detach anomalies
"""

import sys
import os
import re
import struct
import numpy as np
import pandas as pd
from datetime import datetime, timedelta
from collections import defaultdict, Counter
from sklearn.ensemble import IsolationForest
from sklearn.cluster import DBSCAN
from sklearn.svm import OneClassSVM
from sklearn.neighbors import LocalOutlierFactor
from sklearn.preprocessing import StandardScaler
import warnings
warnings.filterwarnings('ignore')
import clickhouse_connect

class UnifiedL1Analyzer:
    """Unified anomaly detection for both PCAP and HDF5 text files"""

    def __init__(self):
        self.DU_MAC = "00:11:22:33:44:67"
        self.RU_MAC = "6c:ad:ad:00:03:2a"
        self.scaler = StandardScaler()

        # Initialize ML models
        self.isolation_forest = IsolationForest(contamination=0.1, random_state=42)
        self.dbscan = DBSCAN(eps=0.5, min_samples=5)
        self.one_class_svm = OneClassSVM(nu=0.1, gamma='auto')
        self.lof = LocalOutlierFactor(n_neighbors=20, contamination=0.1)

        # Initialize ClickHouse client
        try:
            self.clickhouse_client = clickhouse_connect.get_client(
                host=os.getenv('CLICKHOUSE_HOST', 'clickhouse-service'),
                port=int(os.getenv('CLICKHOUSE_PORT', '8123')),
                username=os.getenv('CLICKHOUSE_USERNAME', 'default'),
                password=os.getenv('CLICKHOUSE_PASSWORD', ''),
                database=os.getenv('CLICKHOUSE_DATABASE', 'l1_anomaly_detection')
            )
            print("ClickHouse connection established")
        except Exception as e:
            print(f"Warning: Could not connect to ClickHouse: {e}")
            self.clickhouse_client = None

        print("UNIFIED L1 ANOMALY DETECTION SYSTEM INITIALIZED")
        print("Supports: PCAP files (.pcap, .cap) and HDF5 text files (.txt, .log)")
        print("Algorithms: Isolation Forest, DBSCAN, One-Class SVM, Local Outlier Factor")
        print("Target: DU-RU communication failures and UE event anomalies")

    def detect_file_type(self, file_path):
        """Automatically detect file type based on extension and content"""
        file_ext = os.path.splitext(file_path)[1].lower()

        if file_ext in ['.pcap', '.cap']:
            return 'pcap'
        elif file_ext in ['.txt', '.log']:
            return 'text'
        else:
            # Try to detect PCAP magic bytes
            try:
                with open(file_path, 'rb') as f:
                    header = f.read(8)
                    # PCAP magic numbers (little/big endian)
                    if (header.startswith(b'\xa1\xb2\xc3\xd4') or
                        header.startswith(b'\xd4\xc3\xb2\xa1') or
                        header.startswith(b'\x0a\x0d\x0d\x0a')):  # PCAPNG
                        return 'pcap'
            except:
                pass

            # Default to text
            return 'text'

    def analyze_file(self, file_path):
        """Main analysis function - automatically detects and processes file type"""
        if not os.path.exists(file_path):
            print(f"Error: File '{file_path}' not found")
            return

        file_type = self.detect_file_type(file_path)
        print(f"Detected file type: {file_type.upper()}")

        if file_type == 'pcap':
            self.analyze_pcap_file(file_path)
        else:
            self.analyze_text_file(file_path)

    def analyze_pcap_file(self, pcap_file):
        """Analyze PCAP file for DU-RU communication anomalies"""
        print(f"\nPCAP ANOMALY ANALYSIS")
        print("=" * 30)
        print(f"Processing: {pcap_file}")

        try:
            # Basic PCAP parsing without Scapy
            packets = self.parse_pcap_basic(pcap_file)

            if not packets:
                print("No DU-RU packets found in PCAP file")
                return

            print(f"Extracted {len(packets)} DU-RU packets")

            # Extract features from packets
            features, packet_metadata = self.extract_pcap_features_basic(packets)

            if len(features) < 5:
                print("Insufficient time windows for PCAP analysis")
                return

            # Apply ML algorithms
            features_array = np.array(features)
            features_scaled = self.scaler.fit_transform(features_array)

            # Run all algorithms
            iso_predictions = self.isolation_forest.fit_predict(features_scaled)
            dbscan_labels = self.dbscan.fit_predict(features_scaled)
            svm_predictions = self.one_class_svm.fit_predict(features_scaled)
            lof_predictions = self.lof.fit_predict(features_scaled)

            # Ensemble voting for high confidence
            anomalies = self.find_ensemble_anomalies(
                iso_predictions, dbscan_labels, svm_predictions, lof_predictions
            )

            # Report results
            self.report_pcap_anomalies(anomalies, features, packet_metadata)

        except Exception as e:
            print(f"PCAP analysis error: {e}")
            print("For complete PCAP analysis, use ml_anomaly_detection.py")

    def parse_pcap_basic(self, pcap_file):
        """Basic PCAP parsing without Scapy - extracts DU-RU packets"""
        packets = []

        try:
            with open(pcap_file, 'rb') as f:
                # Read PCAP global header
                global_header = f.read(24)
                if len(global_header) < 24:
                    print("Invalid PCAP file: insufficient header")
                    return []

                # Check magic number
                magic = struct.unpack('I', global_header[:4])[0]
                if magic not in [0xa1b2c3d4, 0xd4c3b2a1]:
                    print("Invalid PCAP file: wrong magic number")
                    return []

                packet_num = 0
                timestamp_offset = 0

                while True:
                    # Read packet header
                    packet_header = f.read(16)
                    if len(packet_header) < 16:
                        break

                    # Parse packet header
                    ts_sec, ts_usec, caplen, origlen = struct.unpack('IIII', packet_header)
                    timestamp = ts_sec + ts_usec / 1000000.0

                    # Read packet data
                    packet_data = f.read(caplen)
                    if len(packet_data) < caplen:
                        break

                    packet_num += 1

                    # Basic Ethernet frame parsing
                    if len(packet_data) >= 14:  # Minimum Ethernet frame
                        # Extract MAC addresses (first 12 bytes)
                        dst_mac = packet_data[0:6].hex(':')
                        src_mac = packet_data[6:12].hex(':')

                        # Check if this is DU-RU communication
                        if (src_mac.lower() in [self.DU_MAC.lower(), self.RU_MAC.lower()] and
                            dst_mac.lower() in [self.DU_MAC.lower(), self.RU_MAC.lower()]):

                            packet_info = {
                                'packet_num': packet_num,
                                'timestamp': timestamp,
                                'size': caplen,
                                'src_mac': src_mac.lower(),
                                'dst_mac': dst_mac.lower(),
                                'direction': 'DU_TO_RU' if src_mac.lower() == self.DU_MAC.lower() else 'RU_TO_DU'
                            }
                            packets.append(packet_info)

        except Exception as e:
            print(f"Error parsing PCAP: {e}")
            return []

        return packets

    def extract_pcap_features_basic(self, packets):
        """Extract basic features from parsed PCAP packets"""
        features = []
        packet_metadata = []

        # Group packets by time windows (100ms)
        time_windows = {}

        for packet in packets:
            timestamp = packet['timestamp']
            time_window = int(timestamp * 10) / 10

            if time_window not in time_windows:
                time_windows[time_window] = {'du_packets': [], 'ru_packets': []}

            if packet['direction'] == 'DU_TO_RU':
                time_windows[time_window]['du_packets'].append(packet)
            else:
                time_windows[time_window]['ru_packets'].append(packet)

        # Calculate features for each window
        for window_time, window_data in time_windows.items():
            du_packets = window_data['du_packets']
            ru_packets = window_data['ru_packets']

            if not du_packets and not ru_packets:
                continue

            window_features = self.calculate_basic_window_features(du_packets, ru_packets)
            if window_features:
                features.append(window_features)
                packet_metadata.append({
                    'window_time': window_time,
                    'du_packets': du_packets,
                    'ru_packets': ru_packets,
                    'packet_count': len(du_packets) + len(ru_packets)
                })

        return features, packet_metadata

    def calculate_basic_window_features(self, du_packets, ru_packets):
        """Calculate basic features for a time window"""
        du_count = len(du_packets)
        ru_count = len(ru_packets)

        # Basic communication features
        communication_ratio = ru_count / du_count if du_count > 0 else 0
        missing_responses = max(0, du_count - ru_count)

        # Timing features (basic approximation)
        all_packets = du_packets + ru_packets
        if len(all_packets) > 1:
            timestamps = [pkt['timestamp'] for pkt in all_packets]
            timestamps.sort()
            inter_arrival_times = np.diff(timestamps)
            avg_inter_arrival = np.mean(inter_arrival_times)
            jitter = np.std(inter_arrival_times)
            max_gap = np.max(inter_arrival_times)
            min_gap = np.min(inter_arrival_times)
        else:
            avg_inter_arrival = jitter = max_gap = min_gap = 0

        # Response time estimation (simplified)
        estimated_response_time = 0
        response_violations = 0
        if du_packets and ru_packets:
            # Simple estimation based on packet order
            for du_pkt in du_packets:
                for ru_pkt in ru_packets:
                    if ru_pkt['timestamp'] > du_pkt['timestamp']:
                        resp_time = (ru_pkt['timestamp'] - du_pkt['timestamp']) * 1000000
                        estimated_response_time = max(estimated_response_time, resp_time)
                        if resp_time > 100:  # 100μs threshold
                            response_violations += 1
                        break

        # Size features
        packet_sizes = [pkt['size'] for pkt in all_packets]
        if packet_sizes:
            avg_size = np.mean(packet_sizes)
            size_variance = np.var(packet_sizes)
            max_size = np.max(packet_sizes)
            min_size = np.min(packet_sizes)
        else:
            avg_size = size_variance = max_size = min_size = 0

        # Return simplified 12 features (instead of 16)
        return [
            du_count, ru_count, communication_ratio, missing_responses,
            avg_inter_arrival, jitter, max_gap, min_gap,
            estimated_response_time, response_violations,
            avg_size, size_variance
        ]

    def analyze_text_file(self, text_file):
        """Analyze HDF5-converted text file for UE event anomalies"""
        print(f"\nUE EVENT ANOMALY ANALYSIS")
        print("=" * 30)
        print(f"Processing: {text_file}")

        try:
            # Parse UE events
            events = self.parse_ue_events_from_text(text_file)

            if not events:
                print("No UE events found in file")
                return

            # Analyze patterns
            results = self.analyze_ue_event_patterns(events)

            # Report anomalies
            self.report_ue_anomalies(results)

        except Exception as e:
            print(f"UE event analysis error: {e}")

    def parse_ue_events_from_text(self, text_file):
        """Parse UE events from HDF5-converted text file"""
        events = []
        line_number = 0

        print(f"Parsing UE events from: {text_file}")

        # Event patterns to detect
        event_patterns = {
            'attach_request': [r'attach.?request', r'rrc.?connection.?request', r'initial.?ue.?message'],
            'attach_accept': [r'attach.?accept', r'rrc.?connection.?setup'],
            'attach_complete': [r'attach.?complete', r'rrc.?connection.?setup.?complete'],
            'detach_request': [r'detach.?request', r'ue.?context.?release.?request'],
            'detach_accept': [r'detach.?accept', r'ue.?context.?release.?complete'],
            'handover_request': [r'handover.?request', r'x2.?handover.?request'],
            'handover_complete': [r'handover.?complete', r'path.?switch.?request.?ack'],
            'paging_request': [r'paging', r'paging.?request'],
            'service_request': [r'service.?request', r'nas.?service.?request'],
            'context_failure': [r'context.?setup.?failure', r'context.?failure', r'setup.?failure']
        }

        try:
            with open(text_file, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    line_number += 1
                    line_lower = line.strip().lower()

                    if not line_lower:
                        continue

                    # Extract timestamp
                    timestamp = self._extract_timestamp(line_lower) or line_number * 0.001

                    # Extract UE identifier
                    ue_id = self._extract_ue_identifier(line_lower) or f'ue_{line_number}'

                    # Extract cell information
                    cell_id = self._extract_cell_info(line_lower) or 'unknown'

                    # Detect event type
                    event_type = None
                    for event_name, patterns in event_patterns.items():
                        for pattern in patterns:
                            if re.search(pattern, line_lower, re.IGNORECASE):
                                event_type = event_name
                                break
                        if event_type:
                            break

                    # Extract cause code
                    cause_code = self._extract_cause_code(line_lower)

                    # Check for DU-RU MAC addresses
                    has_du_mac = self.DU_MAC.lower() in line_lower
                    has_ru_mac = self.RU_MAC.lower() in line_lower

                    if event_type or ue_id != f'ue_{line_number}' or has_du_mac or has_ru_mac:
                        event = {
                            'line_number': line_number,
                            'timestamp': timestamp,
                            'event_type': event_type or 'unknown',
                            'ue_id': ue_id,
                            'cell_id': cell_id,
                            'cause_code': cause_code,
                            'message_size': len(line),
                            'has_du_mac': has_du_mac,
                            'has_ru_mac': has_ru_mac,
                            'raw_line': line[:200]
                        }
                        events.append(event)

        except Exception as e:
            print(f"Error parsing file: {e}")
            return []

        print(f"Extracted {len(events)} UE events from {line_number} lines")
        return events

    def _extract_timestamp(self, line):
        """Extract timestamp from various formats"""
        patterns = [
            r'(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}\.?\d*)',
            r'(\d{10}\.\d+)',
            r'(\d{2}:\d{2}:\d{2}\.?\d*)',
            r'timestamp[:\s=]*(\d+\.?\d*)',
            r'time[:\s=]*(\d+\.?\d*)'
        ]

        for pattern in patterns:
            match = re.search(pattern, line, re.IGNORECASE)
            if match:
                try:
                    timestamp_str = match.group(1)
                    if '.' in timestamp_str and len(timestamp_str.split('.')[0]) == 10:
                        return float(timestamp_str)
                    elif ':' in timestamp_str:
                        time_parts = timestamp_str.split(':')
                        return float(time_parts[0]) * 3600 + float(time_parts[1]) * 60 + float(time_parts[2].split('.')[0])
                except:
                    continue
        return None

    def _extract_ue_identifier(self, line):
        """Extract UE identifier"""
        patterns = [
            r'imsi[:\s=]*(\d+)',
            r'rnti[:\s=]*(\d+)',
            r'ue.?id[:\s=]*(\d+)',
            r'subscriber[:\s=]*(\d+)'
        ]

        for pattern in patterns:
            match = re.search(pattern, line, re.IGNORECASE)
            if match:
                return match.group(1)
        return None

    def _extract_cell_info(self, line):
        """Extract cell information"""
        patterns = [
            r'cell.?id[:\s=]*(\d+)',
            r'enb.?id[:\s=]*(\d+)',
            r'gnb.?id[:\s=]*(\d+)'
        ]

        for pattern in patterns:
            match = re.search(pattern, line, re.IGNORECASE)
            if match:
                return match.group(1)
        return None

    def _extract_cause_code(self, line):
        """Extract cause codes"""
        patterns = [
            r'cause[:\s=]*(\d+)',
            r'error[:\s=]*(\d+)',
            r'failure[:\s=]*(\d+)'
        ]

        for pattern in patterns:
            match = re.search(pattern, line, re.IGNORECASE)
            if match:
                return int(match.group(1))
        return 0

    def analyze_ue_event_patterns(self, events):
        """Analyze UE events for anomalous patterns"""
        if len(events) < 5:
            return {'events': events, 'anomalous_ues': 0}

        # Group events by UE ID
        ue_patterns = defaultdict(list)
        for event in events:
            ue_patterns[event['ue_id']].append(event)

        # Extract features for each UE
        ue_features = []
        ue_metadata = []

        for ue_id, ue_events in ue_patterns.items():
            if len(ue_events) < 2:
                continue

            ue_events.sort(key=lambda x: x['timestamp'])
            features = self._extract_ue_features(ue_events)

            if features:
                ue_features.append(features)
                ue_metadata.append({
                    'ue_id': ue_id,
                    'event_count': len(ue_events),
                    'events': ue_events
                })

        if len(ue_features) < 3:
            return {'events': events, 'anomalous_ues': 0, 'ue_metadata': ue_metadata}

        # Apply ML algorithms
        features_array = np.array(ue_features)
        features_scaled = self.scaler.fit_transform(features_array)

        # Isolation Forest and DBSCAN for UE events
        iso_predictions = self.isolation_forest.fit_predict(features_scaled)
        dbscan_labels = self.dbscan.fit_predict(features_scaled)

        iso_anomalies = set(np.where(iso_predictions == -1)[0])
        dbscan_anomalies = set(np.where(dbscan_labels == -1)[0])

        anomalous_ues = iso_anomalies | dbscan_anomalies

        return {
            'total_events': len(events),
            'total_ues': len(ue_patterns),
            'anomalous_ues': len(anomalous_ues),
            'anomalous_indices': anomalous_ues,
            'ue_metadata': ue_metadata,
            'events': events
        }

    def _extract_ue_features(self, ue_events):
        """Extract 12 features for UE analysis"""
        if len(ue_events) < 2:
            return None

        event_types = [event['event_type'] for event in ue_events]
        event_counts = Counter(event_types)

        timestamps = [event['timestamp'] for event in ue_events]
        time_diffs = np.diff(timestamps)

        # Calculate features
        attach_requests = event_counts.get('attach_request', 0)
        attach_accepts = event_counts.get('attach_accept', 0)
        attach_completes = event_counts.get('attach_complete', 0)
        detach_requests = event_counts.get('detach_request', 0)
        detach_accepts = event_counts.get('detach_accept', 0)
        failures = event_counts.get('context_failure', 0)

        return [
            len(ue_events),
            attach_requests,
            attach_accepts,
            attach_completes,
            detach_requests,
            detach_accepts,
            failures,
            attach_requests - attach_accepts,
            detach_requests - detach_accepts,
            np.mean(time_diffs) if len(time_diffs) > 0 else 0,
            np.std(time_diffs) if len(time_diffs) > 0 else 0,
            sum(1 for event in ue_events if event['cause_code'] > 0)
        ]

    def find_ensemble_anomalies(self, iso_pred, dbscan_labels, svm_pred, lof_pred):
        """Find high-confidence anomalies using ensemble voting"""
        anomalies = []
        total_samples = len(iso_pred)

        for i in range(total_samples):
            votes = 0
            if iso_pred[i] == -1: votes += 1
            if dbscan_labels[i] == -1: votes += 1
            if svm_pred[i] == -1: votes += 1
            if lof_pred[i] == -1: votes += 1

            if votes >= 2:  # High confidence threshold
                anomalies.append(i)

        return anomalies

    def report_pcap_anomalies(self, anomalies, features, metadata):
        """Report PCAP anomalies"""
        print(f"\nPCAP ANOMALY ANALYSIS RESULTS")
        print("=" * 50)
        print(f"Time Windows Analyzed: {len(features)}")
        print(f"High-Confidence Anomalies: {len(anomalies)}")

        if not anomalies:
            print("No high-confidence PCAP anomalies detected")
            return

        print(f"\nANOMALOUS TIME WINDOWS:")
        print("-" * 30)

        for idx in sorted(anomalies):
            if idx >= len(metadata):
                continue

            window_info = metadata[idx]
            window_features = features[idx]

            # Get representative packet for line number
            all_packets = window_info['du_packets'] + window_info['ru_packets']
            if all_packets:
                line_number = min(pkt['packet_num'] for pkt in all_packets)
            else:
                line_number = idx + 1

            print(f"\nLINE {line_number}: PCAP ANOMALY DETECTED")
            print(f"*** FRONTHAUL ISSUE BETWEEN DU TO RU ***")
            print(f"DU MAC: {self.DU_MAC}")
            print(f"RU MAC: {self.RU_MAC}")
            print(f"Time Window: {window_info['window_time']:.3f}s")
            print(f"Packet Count: {window_info['packet_count']}")

            # Analyze specific issues
            du_count, ru_count, comm_ratio, missing_resp = window_features[:4]

            issues = []
            if missing_resp > 0:
                issues.append(f"Missing Responses: {int(missing_resp)} DU packets without RU replies")
            if comm_ratio < 0.8 and du_count > 0:
                issues.append(f"Poor Communication Ratio: {comm_ratio:.2f} (expected > 0.8)")

            if issues:
                print("DETECTED ISSUES:")
                for issue in issues:
                    print(f"  • {issue}")
            else:
                print("ISSUE TYPE: Statistical deviation from normal DU-RU patterns")

    def report_ue_anomalies(self, results):
        """Report UE anomalies"""
        print(f"\nUE EVENT ANOMALY ANALYSIS RESULTS")
        print("=" * 50)
        print(f"Total Events Analyzed: {results['total_events']}")
        print(f"Total UEs: {results['total_ues']}")
        print(f"Anomalous UEs Detected: {results['anomalous_ues']}")

        if results['anomalous_ues'] == 0:
            print("No anomalous UE behavior detected")
            return

        print(f"\nANOMALOUS UE PATTERNS:")
        print("-" * 30)

        for idx in sorted(results['anomalous_indices']):
            if idx >= len(results['ue_metadata']):
                continue

            ue_info = results['ue_metadata'][idx]
            ue_events = ue_info['events']

            print(f"\nLINE {ue_events[0]['line_number']}: UE ANOMALY DETECTED")
            print(f"*** FRONTHAUL ISSUE BETWEEN DU TO RU ***")
            print(f"DU MAC: {self.DU_MAC}")
            print(f"RU MAC: {self.RU_MAC}")
            print(f"UE ID: {ue_info['ue_id']}")
            print(f"Event Count: {ue_info['event_count']}")

            # Analyze issues
            event_types = [event['event_type'] for event in ue_events]
            event_counts = Counter(event_types)

            attach_requests = event_counts.get('attach_request', 0)
            attach_accepts = event_counts.get('attach_accept', 0)
            detach_requests = event_counts.get('detach_request', 0)
            failures = event_counts.get('context_failure', 0)

            du_events = sum(1 for event in ue_events if event['has_du_mac'])
            ru_events = sum(1 for event in ue_events if event['has_ru_mac'])

            if du_events > 0 or ru_events > 0:
                print(f"DU Events: {du_events}, RU Events: {ru_events}")

            issues = []
            if attach_requests > attach_accepts + 1:
                issues.append(f"Failed Attach Procedures: {attach_requests - attach_accepts} incomplete")
            if failures > 0:
                issues.append(f"Context Failures: {failures} detected")
            if detach_requests == 0 and attach_requests > 0:
                issues.append("Missing Detach Events: UE may have unexpectedly disconnected")

            if issues:
                print("DETECTED ISSUES:")
                for issue in issues:
                    print(f"  • {issue}")
            else:
                print("ISSUE TYPE: Abnormal UE Event Pattern")
                print("DETAILS: Statistical deviation from normal UE behavior")

            # Show event sequence
            print("Event Sequence:")
            for i, event in enumerate(ue_events[:5]):
                print(f"  {i+1}. {event['event_type']} at line {event['line_number']}")
            if len(ue_events) > 5:
                print(f"  ... and {len(ue_events) - 5} more events")

def main():
    if len(sys.argv) != 2:
        print("UNIFIED L1 ANOMALY DETECTION SYSTEM")
        print("=" * 40)
        print("Usage: python unified_l1_analyzer.py <file_path>")
        print()
        print("Supported formats:")
        print("• PCAP files (.pcap, .cap) - DU-RU communication analysis")
        print("• Text files (.txt, .log) - UE Attach/Detach event analysis")
        print()
        print("Examples:")
        print("  python unified_l1_analyzer.py network_capture.pcap")
        print("  python unified_l1_analyzer.py ue_events.txt")
        print()
        print("Note: For full PCAP analysis with advanced features,")
        print("      use ml_anomaly_detection.py (requires Scapy)")
        sys.exit(1)

    file_path = sys.argv[1]

    if not os.path.exists(file_path):
        print(f"Error: File '{file_path}' not found")
        sys.exit(1)

    # Initialize and run unified analysis
    analyzer = UnifiedL1Analyzer()
    analyzer.analyze_file(file_path)

    print(f"\nUNIFIED L1 ANALYSIS COMPLETE")
    print("System provides comprehensive L1 troubleshooting for:")
    print("• DU-RU fronthaul communication issues (PCAP)")
    print("• UE mobility and attachment anomalies (Text)")

if __name__ == "__main__":
    main()
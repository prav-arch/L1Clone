#!/usr/bin/env python3

import sys
import argparse
import uuid
from scapy.all import rdpcap, Ether
from datetime import datetime
import json
import re
from clickhouse_client import clickhouse_client

class PCAPProcessor:
    def __init__(self):
        self.anomalies_detected = []
        self.mac_patterns = {
            'suspicious_oui': ['00:00:00', 'FF:FF:FF', '00:11:22'],  # Suspicious OUIs
            'broadcast_excessive': 'FF:FF:FF:FF:FF:FF',
            'multicast_pattern': '^01:',
            'local_admin': '^02:'  # Locally administered MAC addresses
        }
    
    def analyze_mac_addresses(self, packets):
        """Analyze MAC address patterns for anomalies"""
        mac_stats = {}
        broadcast_count = 0
        multicast_count = 0
        local_admin_count = 0
        
        for packet in packets:
            if Ether in packet:
                src_mac = packet[Ether].src
                dst_mac = packet[Ether].dst
                
                # Count MAC address occurrences
                mac_stats[src_mac] = mac_stats.get(src_mac, 0) + 1
                mac_stats[dst_mac] = mac_stats.get(dst_mac, 0) + 1
                
                # Check for broadcast traffic
                if dst_mac == self.mac_patterns['broadcast_excessive']:
                    broadcast_count += 1
                
                # Check for multicast traffic
                if re.match(self.mac_patterns['multicast_pattern'], dst_mac):
                    multicast_count += 1
                
                # Check for locally administered addresses
                if re.match(self.mac_patterns['local_admin'], src_mac):
                    local_admin_count += 1
        
        return {
            'mac_stats': mac_stats,
            'broadcast_count': broadcast_count,
            'multicast_count': multicast_count,
            'local_admin_count': local_admin_count
        }
    
    def detect_fronthaul_issues(self, packets, source_file):
        """Detect fronthaul communication issues between DU and RU"""
        du_ru_communications = []
        timing_violations = []
        protocol_issues = []
        
        prev_timestamp = None
        
        for packet in packets:
            if hasattr(packet, 'time'):
                current_timestamp = packet.time
                
                if prev_timestamp:
                    latency = current_timestamp - prev_timestamp
                    
                    # Check for excessive latency (> 1ms for fronthaul)
                    if latency > 0.001:
                        timing_violations.append({
                            'timestamp': current_timestamp,
                            'latency': latency,
                            'src_mac': packet[Ether].src if Ether in packet else 'unknown',
                            'dst_mac': packet[Ether].dst if Ether in packet else 'unknown'
                        })
                
                prev_timestamp = current_timestamp
        
        # Generate anomalies for timing violations
        if timing_violations:
            for violation in timing_violations[:10]:  # Limit to top 10
                anomaly_id = str(uuid.uuid4())
                anomaly = {
                    'id': anomaly_id,
                    'timestamp': datetime.fromtimestamp(violation['timestamp']),
                    'type': 'fronthaul',
                    'description': f"High latency detected between DU and RU: {violation['latency']:.4f}s",
                    'severity': 'high' if violation['latency'] > 0.005 else 'medium',
                    'source_file': source_file,
                    'mac_address': violation['src_mac'],
                    'ue_id': None,
                    'details': json.dumps({
                        'latency_ms': violation['latency'] * 1000,
                        'src_mac': violation['src_mac'],
                        'dst_mac': violation['dst_mac']
                    }),
                    'status': 'open'
                }
                
                self.anomalies_detected.append(anomaly)
                clickhouse_client.insert_anomaly(anomaly)
        
        return len(timing_violations)
    
    def detect_mac_anomalies(self, mac_analysis, source_file):
        """Detect MAC address related anomalies"""
        anomaly_count = 0
        
        # Check for suspicious OUIs
        for mac, count in mac_analysis['mac_stats'].items():
            oui = mac[:8].upper()
            if oui in [pattern.upper() for pattern in self.mac_patterns['suspicious_oui']]:
                anomaly_id = str(uuid.uuid4())
                anomaly = {
                    'id': anomaly_id,
                    'timestamp': datetime.now(),
                    'type': 'mac_address',
                    'description': f"Suspicious MAC address pattern detected: {mac}",
                    'severity': 'medium',
                    'source_file': source_file,
                    'mac_address': mac,
                    'ue_id': None,
                    'details': json.dumps({
                        'packet_count': count,
                        'oui': oui,
                        'reason': 'suspicious_oui'
                    }),
                    'status': 'open'
                }
                
                self.anomalies_detected.append(anomaly)
                clickhouse_client.insert_anomaly(anomaly)
                anomaly_count += 1
        
        # Check for excessive broadcast traffic
        total_packets = sum(mac_analysis['mac_stats'].values()) // 2  # Divide by 2 as we count both src and dst
        if total_packets > 0:
            broadcast_ratio = mac_analysis['broadcast_count'] / total_packets
            
            if broadcast_ratio > 0.1:  # More than 10% broadcast traffic
                anomaly_id = str(uuid.uuid4())
                anomaly = {
                    'id': anomaly_id,
                    'timestamp': datetime.now(),
                    'type': 'protocol',
                    'description': f"Excessive broadcast traffic detected: {broadcast_ratio:.2%}",
                    'severity': 'medium',
                    'source_file': source_file,
                    'mac_address': 'FF:FF:FF:FF:FF:FF',
                    'ue_id': None,
                    'details': json.dumps({
                        'broadcast_count': mac_analysis['broadcast_count'],
                        'total_packets': total_packets,
                        'broadcast_ratio': broadcast_ratio
                    }),
                    'status': 'open'
                }
                
                self.anomalies_detected.append(anomaly)
                clickhouse_client.insert_anomaly(anomaly)
                anomaly_count += 1
        
        return anomaly_count
    
    def process_pcap(self, pcap_file_path, source_file):
        """Main processing function for PCAP files"""
        try:
            print(f"Processing PCAP file: {pcap_file_path}")
            packets = rdpcap(pcap_file_path)
            print(f"Loaded {len(packets)} packets")
            
            # Analyze MAC addresses
            mac_analysis = self.analyze_mac_addresses(packets)
            
            # Detect fronthaul issues
            fronthaul_anomalies = self.detect_fronthaul_issues(packets, source_file)
            
            # Detect MAC address anomalies
            mac_anomalies = self.detect_mac_anomalies(mac_analysis, source_file)
            
            total_anomalies = fronthaul_anomalies + mac_anomalies
            
            # Create session record
            session_id = str(uuid.uuid4())
            session_data = {
                'id': str(uuid.uuid4()),
                'session_id': session_id,
                'start_time': datetime.now(),
                'end_time': datetime.now(),
                'packets_analyzed': len(packets),
                'anomalies_detected': total_anomalies,
                'source_file': source_file
            }
            
            clickhouse_client.client.insert('sessions', [session_data])
            
            print(f"Processing complete. Found {total_anomalies} anomalies.")
            return total_anomalies
            
        except Exception as e:
            print(f"Error processing PCAP file: {str(e)}")
            raise e

def main():
    parser = argparse.ArgumentParser(description='Process PCAP files for network anomaly detection')
    parser.add_argument('--file-id', required=True, help='File ID from database')
    parser.add_argument('--filename', required=True, help='Original filename')
    
    args = parser.parse_args()
    
    # Read file path from stdin
    pcap_file_path = sys.stdin.read().strip()
    
    processor = PCAPProcessor()
    
    try:
        anomalies_found = processor.process_pcap(pcap_file_path, args.filename)
        print(f"SUCCESS: {anomalies_found} anomalies detected")
        sys.exit(0)
    except Exception as e:
        print(f"ERROR: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()

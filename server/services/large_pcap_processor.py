
#!/usr/bin/env python3

import sys
import argparse
import uuid
import os
from scapy.all import PcapReader, Ether, IP
from datetime import datetime
import json
from clickhouse_client import clickhouse_client

class LargePCAPProcessor:
    def __init__(self, chunk_size=10000):
        self.chunk_size = chunk_size
        self.anomalies_detected = []
        
    def process_large_pcap_chunked(self, pcap_file_path, source_file):
        """Process large PCAP files in chunks to avoid memory issues"""
        try:
            print(f"Processing large PCAP file in chunks: {pcap_file_path}")
            
            total_packets = 0
            total_anomalies = 0
            chunk_number = 0
            
            # Use PcapReader for streaming instead of rdpcap
            with PcapReader(pcap_file_path) as pcap_reader:
                chunk_packets = []
                
                for packet in pcap_reader:
                    chunk_packets.append(packet)
                    total_packets += 1
                    
                    # Process chunk when it reaches chunk_size
                    if len(chunk_packets) >= self.chunk_size:
                        chunk_anomalies = self.process_packet_chunk(
                            chunk_packets, source_file, chunk_number
                        )
                        total_anomalies += chunk_anomalies
                        
                        # Send chunk summary to LLM for analysis
                        self.send_chunk_to_llm(chunk_packets, chunk_number, source_file)
                        
                        chunk_packets = []
                        chunk_number += 1
                        
                        print(f"Processed chunk {chunk_number}: {self.chunk_size} packets")
                
                # Process remaining packets
                if chunk_packets:
                    chunk_anomalies = self.process_packet_chunk(
                        chunk_packets, source_file, chunk_number
                    )
                    total_anomalies += chunk_anomalies
                    self.send_chunk_to_llm(chunk_packets, chunk_number, source_file)
            
            # Create session record
            session_id = str(uuid.uuid4())
            session_data = {
                'id': str(uuid.uuid4()),
                'session_id': session_id,
                'start_time': datetime.now(),
                'end_time': datetime.now(),
                'packets_analyzed': total_packets,
                'anomalies_detected': total_anomalies,
                'source_file': source_file
            }
            
            clickhouse_client.client.insert('sessions', [session_data])
            
            print(f"Large PCAP processing complete:")
            print(f"- Total packets: {total_packets}")
            print(f"- Total chunks: {chunk_number + 1}")
            print(f"- Total anomalies: {total_anomalies}")
            
            return total_anomalies
            
        except Exception as e:
            print(f"Error processing large PCAP file: {str(e)}")
            raise e
    
    def process_packet_chunk(self, packets, source_file, chunk_number):
        """Process a chunk of packets for anomalies"""
        anomaly_count = 0
        
        # Basic fronthaul timing analysis
        prev_timestamp = None
        
        for i, packet in enumerate(packets):
            if hasattr(packet, 'time'):
                current_timestamp = packet.time
                
                if prev_timestamp:
                    latency = current_timestamp - prev_timestamp
                    
                    # Check for timing violations
                    if latency > 0.001:  # > 1ms
                        anomaly_id = str(uuid.uuid4())
                        anomaly = {
                            'id': anomaly_id,
                            'timestamp': datetime.fromtimestamp(current_timestamp),
                            'type': 'fronthaul',
                            'description': f"Chunk {chunk_number}: High latency {latency:.4f}s",
                            'severity': 'high' if latency > 0.005 else 'medium',
                            'source_file': source_file,
                            'mac_address': packet[Ether].src if Ether in packet else None,
                            'ue_id': None,
                            'details': json.dumps({
                                'chunk_number': chunk_number,
                                'packet_index': i,
                                'latency_ms': latency * 1000
                            }),
                            'status': 'open'
                        }
                        
                        self.anomalies_detected.append(anomaly)
                        clickhouse_client.insert_anomaly(anomaly)
                        anomaly_count += 1
                
                prev_timestamp = current_timestamp
        
        return anomaly_count
    
    def send_chunk_to_llm(self, packets, chunk_number, source_file):
        """Send chunk summary to LLM for analysis"""
        try:
            # Create chunk summary for LLM
            chunk_summary = {
                'chunk_number': chunk_number,
                'packet_count': len(packets),
                'source_file': source_file,
                'protocols': {},
                'mac_addresses': set(),
                'timing_stats': []
            }
            
            # Extract key features from chunk
            for packet in packets[:100]:  # Sample first 100 packets
                if Ether in packet:
                    chunk_summary['mac_addresses'].add(packet[Ether].src)
                    
                if IP in packet:
                    proto = 'TCP' if hasattr(packet, 'tcp') else 'UDP' if hasattr(packet, 'udp') else 'IP'
                    chunk_summary['protocols'][proto] = chunk_summary['protocols'].get(proto, 0) + 1
            
            chunk_summary['mac_addresses'] = list(chunk_summary['mac_addresses'])
            
            # Create prompt for LLM
            prompt = f"""Analyze this chunk of network data:
Chunk: {chunk_number}
Packets: {len(packets)}
Protocols: {chunk_summary['protocols']}
MAC Addresses: {len(chunk_summary['mac_addresses'])}

Identify any patterns or anomalies in this chunk."""
            
            print(f"Chunk {chunk_number} summary prepared for LLM analysis")
            # Here you would send to your remote LLM service
            
        except Exception as e:
            print(f"Error creating chunk summary: {e}")

def main():
    parser = argparse.ArgumentParser(description='Process large PCAP files with chunked analysis')
    parser.add_argument('--file-id', required=True, help='File ID from database')
    parser.add_argument('--filename', required=True, help='Original filename')
    parser.add_argument('--chunk-size', type=int, default=10000, help='Packets per chunk')
    
    args = parser.parse_args()
    
    # Read file path from stdin
    pcap_file_path = sys.stdin.read().strip()
    
    processor = LargePCAPProcessor(chunk_size=args.chunk_size)
    
    try:
        anomalies_found = processor.process_large_pcap_chunked(pcap_file_path, args.filename)
        print(f"SUCCESS: {anomalies_found} anomalies detected from large file")
        sys.exit(0)
    except Exception as e:
        print(f"ERROR: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()

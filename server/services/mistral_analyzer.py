#!/usr/bin/env python3

import sys
import argparse
import json
import uuid
from datetime import datetime
from scapy.all import rdpcap, Ether, IP, TCP, UDP
from clickhouse_client import clickhouse_client
import requests
import subprocess
import os

class MistralPCAPAnalyzer:
    def __init__(self, model_path="/tmp/llm_models/mistral-7b-instruct-v0.2.Q4_K_M.gguf"):
        self.model_path = model_path
        self.anomalies_detected = []
        
    def extract_packet_features(self, packets):
        """Extract meaningful features from PCAP packets for LLM analysis"""
        features = {
            'total_packets': len(packets),
            'protocols': {},
            'traffic_patterns': [],
            'timing_analysis': [],
            'mac_addresses': set(),
            'ip_addresses': set(),
            'port_analysis': {},
            'packet_sizes': []
        }
        
        prev_time = None
        
        for i, packet in enumerate(packets[:1000]):  # Limit to first 1000 packets for performance
            packet_info = {
                'index': i,
                'timestamp': float(packet.time) if hasattr(packet, 'time') else 0,
                'size': len(packet)
            }
            
            # Extract protocol information
            if Ether in packet:
                features['mac_addresses'].add(packet[Ether].src)
                features['mac_addresses'].add(packet[Ether].dst)
                packet_info['src_mac'] = packet[Ether].src
                packet_info['dst_mac'] = packet[Ether].dst
                
            if IP in packet:
                features['ip_addresses'].add(packet[IP].src)
                features['ip_addresses'].add(packet[IP].dst)
                packet_info['src_ip'] = packet[IP].src
                packet_info['dst_ip'] = packet[IP].dst
                packet_info['protocol'] = packet[IP].proto
                
                # Count protocols
                proto_name = 'IP'
                if TCP in packet:
                    proto_name = 'TCP'
                    packet_info['src_port'] = packet[TCP].sport
                    packet_info['dst_port'] = packet[TCP].dport
                    port_key = f"{packet[TCP].sport}-{packet[TCP].dport}"
                    features['port_analysis'][port_key] = features['port_analysis'].get(port_key, 0) + 1
                elif UDP in packet:
                    proto_name = 'UDP'
                    packet_info['src_port'] = packet[UDP].sport
                    packet_info['dst_port'] = packet[UDP].dport
                    port_key = f"{packet[UDP].sport}-{packet[UDP].dport}"
                    features['port_analysis'][port_key] = features['port_analysis'].get(port_key, 0) + 1
                
                features['protocols'][proto_name] = features['protocols'].get(proto_name, 0) + 1
            
            # Timing analysis
            if prev_time and hasattr(packet, 'time'):
                inter_packet_time = packet.time - prev_time
                packet_info['inter_packet_time'] = inter_packet_time
                features['timing_analysis'].append(inter_packet_time)
            
            prev_time = packet.time if hasattr(packet, 'time') else None
            features['packet_sizes'].append(len(packet))
            features['traffic_patterns'].append(packet_info)
        
        # Convert sets to lists for JSON serialization
        features['mac_addresses'] = list(features['mac_addresses'])
        features['ip_addresses'] = list(features['ip_addresses'])
        
        return features
    
    def create_llm_prompt(self, features, filename):
        """Create a detailed prompt for the Mistral model to analyze network traffic"""
        
        # Calculate statistics
        avg_packet_size = sum(features['packet_sizes']) / len(features['packet_sizes']) if features['packet_sizes'] else 0
        avg_inter_packet_time = sum(features['timing_analysis']) / len(features['timing_analysis']) if features['timing_analysis'] else 0
        
        prompt = f"""[INST] You are a network security expert analyzing L1 5G network traffic for anomalies. 

PCAP File Analysis Request:
Filename: {filename}
Total Packets: {features['total_packets']}
Unique MAC Addresses: {len(features['mac_addresses'])}
Unique IP Addresses: {len(features['ip_addresses'])}
Protocol Distribution: {json.dumps(features['protocols'])}
Average Packet Size: {avg_packet_size:.2f} bytes
Average Inter-packet Time: {avg_inter_packet_time:.6f} seconds

Sample Traffic Patterns (first 10 packets):
{json.dumps(features['traffic_patterns'][:10], indent=2)}

Top Port Communications:
{json.dumps(dict(list(features['port_analysis'].items())[:10]), indent=2)}

ANALYSIS REQUIREMENTS:
1. Identify potential security threats or network anomalies
2. Check for suspicious MAC address patterns
3. Analyze timing patterns for fronthaul DU-RU communication issues
4. Detect protocol violations or unusual traffic patterns
5. Flag any indicators of network attacks or misconfigurations

Please provide your analysis in JSON format with the following structure:
{{
  "anomalies_found": [
    {{
      "type": "fronthaul|mac_address|protocol|security",
      "severity": "low|medium|high|critical", 
      "description": "Detailed description of the anomaly",
      "affected_entities": ["MAC addresses, IPs, or ports involved"],
      "recommendation": "Suggested action to address this issue"
    }}
  ],
  "overall_assessment": "General network health assessment",
  "confidence_score": 0.85
}}

Focus specifically on L1 5G network issues, fronthaul communications, and potential security threats. [/INST]"""
        
        return prompt
    
    def query_mistral_model(self, prompt):
        """Query the local Mistral model using llama.cpp or similar"""
        try:
            # Using llama.cpp for GGUF model inference
            cmd = [
                "python", "-c", f"""
import subprocess
import sys

# Simple text generation using llama.cpp CLI (adjust path as needed)
cmd = [
    '/usr/local/bin/llama.cpp/main',  # Adjust path to your llama.cpp binary
    '-m', '{self.model_path}',
    '-p', '''{prompt}''',
    '-n', '2048',
    '--temp', '0.3',
    '--ctx-size', '4096'
]

try:
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    print(result.stdout)
except Exception as e:
    print(f"Error: {{e}}")
    sys.exit(1)
"""
            ]
            
            # Alternative: Direct API call if you have a local server running
            # Uncomment and modify this section if you have Mistral running as a web service
            """
            response = requests.post(
                "http://localhost:8080/v1/chat/completions",  # Adjust URL
                json={
                    "model": "mistral-7b-instruct",
                    "messages": [{"role": "user", "content": prompt}],
                    "temperature": 0.3,
                    "max_tokens": 2048
                },
                timeout=60
            )
            return response.json()['choices'][0]['message']['content']
            """
            
            # For now, return a structured response format
            # Replace this with actual model inference
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            return result.stdout.strip()
            
        except subprocess.TimeoutExpired:
            return "Error: Model inference timeout"
        except Exception as e:
            return f"Error querying model: {str(e)}"
    
    def parse_llm_response(self, response_text):
        """Parse the LLM response and extract anomalies"""
        try:
            # Try to extract JSON from the response
            import re
            json_match = re.search(r'\{.*\}', response_text, re.DOTALL)
            if json_match:
                response_data = json.loads(json_match.group())
                return response_data.get('anomalies_found', [])
            else:
                # Fallback: parse unstructured response
                return self.parse_unstructured_response(response_text)
        except Exception as e:
            print(f"Error parsing LLM response: {e}")
            return []
    
    def parse_unstructured_response(self, response_text):
        """Parse unstructured LLM response for anomalies"""
        anomalies = []
        
        # Simple keyword-based extraction
        lines = response_text.split('\n')
        current_anomaly = {}
        
        for line in lines:
            line = line.strip()
            if any(keyword in line.lower() for keyword in ['anomaly', 'threat', 'suspicious', 'violation']):
                if current_anomaly:
                    anomalies.append(current_anomaly)
                current_anomaly = {
                    'type': 'protocol',
                    'severity': 'medium',
                    'description': line,
                    'affected_entities': [],
                    'recommendation': 'Further investigation needed'
                }
        
        if current_anomaly:
            anomalies.append(current_anomaly)
        
        return anomalies
    
    def process_pcap_with_llm(self, pcap_file_path, source_file):
        """Main function to process PCAP with Mistral LLM analysis"""
        try:
            print(f"Processing PCAP file with Mistral LLM: {pcap_file_path}")
            
            # Load and analyze packets
            packets = rdpcap(pcap_file_path)
            print(f"Loaded {len(packets)} packets")
            
            # Extract features
            features = self.extract_packet_features(packets)
            
            # Create LLM prompt
            prompt = self.create_llm_prompt(features, source_file)
            
            # Query Mistral model
            print("Querying Mistral model for anomaly analysis...")
            llm_response = self.query_mistral_model(prompt)
            
            # Parse response
            llm_anomalies = self.parse_llm_response(llm_response)
            
            # Convert LLM anomalies to database format
            total_anomalies = 0
            for anomaly_data in llm_anomalies:
                anomaly_id = str(uuid.uuid4())
                anomaly = {
                    'id': anomaly_id,
                    'timestamp': datetime.now(),
                    'type': anomaly_data.get('type', 'llm_detected'),
                    'description': anomaly_data.get('description', 'LLM detected anomaly'),
                    'severity': anomaly_data.get('severity', 'medium'),
                    'source_file': source_file,
                    'mac_address': anomaly_data.get('affected_entities', [None])[0],
                    'ue_id': None,
                    'details': json.dumps({
                        'llm_analysis': anomaly_data,
                        'confidence': anomaly_data.get('confidence', 0.5),
                        'recommendation': anomaly_data.get('recommendation', '')
                    }),
                    'status': 'open'
                }
                
                self.anomalies_detected.append(anomaly)
                clickhouse_client.insert_anomaly(anomaly)
                total_anomalies += 1
            
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
            
            print(f"Mistral LLM analysis complete. Found {total_anomalies} anomalies.")
            print(f"LLM Response: {llm_response[:500]}...")  # Print first 500 chars
            
            return total_anomalies
            
        except Exception as e:
            print(f"Error in Mistral LLM analysis: {str(e)}")
            raise e

def main():
    parser = argparse.ArgumentParser(description='Process PCAP files with Mistral LLM for advanced anomaly detection')
    parser.add_argument('--file-id', required=True, help='File ID from database')
    parser.add_argument('--filename', required=True, help='Original filename')
    parser.add_argument('--model-path', default='/tmp/llm_models/mistral-7b-instruct-v0.2.Q4_K_M.gguf', 
                        help='Path to Mistral GGUF model')
    
    args = parser.parse_args()
    
    # Read file path from stdin
    pcap_file_path = sys.stdin.read().strip()
    
    analyzer = MistralPCAPAnalyzer(model_path=args.model_path)
    
    try:
        anomalies_found = analyzer.process_pcap_with_llm(pcap_file_path, args.filename)
        print(f"SUCCESS: {anomalies_found} anomalies detected by Mistral LLM")
        sys.exit(0)
    except Exception as e:
        print(f"ERROR: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()
#!/usr/bin/env python3

import sys
import json
import subprocess
import asyncio
import websockets
import threading
from datetime import datetime
from scapy.all import rdpcap, Ether, IP, UDP, Raw
import uuid
from clickhouse_client import clickhouse_client

class StreamingMistralAnalyzer:
    def __init__(self, model_path="/tmp/llm_models/mistral-7b-instruct-v0.2.Q4_K_M.gguf"):
        self.model_path = model_path
        self.websocket_clients = set()
        
    def extract_fronthaul_features(self, packets):
        """Extract DU-RU fronthaul specific features"""
        fronthaul_data = {
            'total_packets': len(packets),
            'du_ru_communications': [],
            'timing_violations': [],
            'cpri_patterns': [],
            'ecpri_flows': [],
            'latency_measurements': [],
            'jitter_analysis': [],
            'packet_loss_indicators': []
        }
        
        prev_timestamp = None
        packet_sequence = []
        
        for i, packet in enumerate(packets):
            packet_info = {
                'index': i,
                'timestamp': float(packet.time) if hasattr(packet, 'time') else 0,
                'size': len(packet)
            }
            
            # Extract MAC and IP information for DU-RU identification
            if Ether in packet:
                packet_info['src_mac'] = packet[Ether].src
                packet_info['dst_mac'] = packet[Ether].dst
                
                # Check for DU-RU communication patterns (specific MAC ranges)
                if self.is_du_ru_communication(packet[Ether].src, packet[Ether].dst):
                    packet_info['communication_type'] = 'DU-RU'
                    fronthaul_data['du_ru_communications'].append(packet_info)
            
            if IP in packet:
                packet_info['src_ip'] = packet[IP].src
                packet_info['dst_ip'] = packet[IP].dst
                
                # Check for eCPRI traffic (typically UDP port 2152 or custom ports)
                if UDP in packet:
                    src_port = packet[UDP].sport
                    dst_port = packet[UDP].dport
                    packet_info['src_port'] = src_port
                    packet_info['dst_port'] = dst_port
                    
                    # eCPRI typical ports: 2152, 4789, or custom ranges
                    if self.is_ecpri_port(src_port) or self.is_ecpri_port(dst_port):
                        packet_info['protocol_type'] = 'eCPRI'
                        fronthaul_data['ecpri_flows'].append(packet_info)
                        
                        # Extract eCPRI header information if present
                        if Raw in packet:
                            ecpri_data = self.parse_ecpri_header(packet[Raw].load)
                            if ecpri_data:
                                packet_info['ecpri_info'] = ecpri_data
            
            # Timing analysis for fronthaul requirements
            if prev_timestamp and hasattr(packet, 'time'):
                latency = packet.time - prev_timestamp
                packet_info['inter_packet_latency'] = latency
                
                # Fronthaul timing requirements (typically < 100μs for 5G)
                if latency > 0.0001:  # > 100μs
                    violation = {
                        'timestamp': packet.time,
                        'latency_us': latency * 1000000,
                        'packet_index': i,
                        'severity': 'critical' if latency > 0.001 else 'high'
                    }
                    fronthaul_data['timing_violations'].append(violation)
                
                fronthaul_data['latency_measurements'].append(latency * 1000000)  # Convert to μs
            
            prev_timestamp = packet.time if hasattr(packet, 'time') else None
            packet_sequence.append(packet_info)
        
        # Calculate jitter (variation in latency)
        if len(fronthaul_data['latency_measurements']) > 1:
            latencies = fronthaul_data['latency_measurements']
            mean_latency = sum(latencies) / len(latencies)
            jitter_values = [abs(lat - mean_latency) for lat in latencies]
            fronthaul_data['jitter_analysis'] = {
                'mean_latency_us': mean_latency,
                'max_jitter_us': max(jitter_values) if jitter_values else 0,
                'avg_jitter_us': sum(jitter_values) / len(jitter_values) if jitter_values else 0
            }
        
        return fronthaul_data
    
    def is_du_ru_communication(self, src_mac, dst_mac):
        """Identify DU-RU communication based on MAC patterns"""
        # Actual DU and RU equipment MAC addresses for this network
        du_patterns = ['00:11:22']  # DU MAC: 00:11:22:33:44:67
        ru_patterns = ['6c:ad:ad']  # RU MAC: 6c:ad:ad:00:03:2a
        
        src_oui = src_mac[:8].lower()
        dst_oui = dst_mac[:8].lower()
        
        return any(pattern in src_oui for pattern in du_patterns) or \
               any(pattern in dst_oui for pattern in ru_patterns)
    
    def is_ecpri_port(self, port):
        """Check if port is commonly used for eCPRI"""
        ecpri_ports = [2152, 4789, 2123, 3386]  # Common eCPRI ports
        return port in ecpri_ports or (5000 <= port <= 5100)  # Custom range
    
    def parse_ecpri_header(self, payload):
        """Parse eCPRI header information"""
        try:
            if len(payload) < 4:
                return None
            
            # Basic eCPRI header parsing
            version = (payload[0] >> 4) & 0x0F
            msg_type = payload[1]
            payload_size = int.from_bytes(payload[2:4], byteorder='big')
            
            return {
                'version': version,
                'message_type': msg_type,
                'payload_size': payload_size,
                'is_valid': version in [1, 2] and msg_type < 8
            }
        except:
            return None
    
    def create_fronthaul_prompt(self, fronthaul_data, filename):
        """Create specialized prompt for DU-RU fronthaul analysis"""
        
        timing_stats = fronthaul_data.get('jitter_analysis', {})
        
        prompt = f"""<s>[INST] You are a 5G RAN specialist analyzing fronthaul network traffic between Distributed Unit (DU) and Radio Unit (RU) for anomalies and performance issues.

FRONTHAUL ANALYSIS DATA:
File: {filename}
Total Packets: {fronthaul_data['total_packets']}
DU-RU Communications: {len(fronthaul_data['du_ru_communications'])}
eCPRI Flows: {len(fronthaul_data['ecpri_flows'])}
Timing Violations: {len(fronthaul_data['timing_violations'])}

TIMING ANALYSIS:
- Mean Latency: {timing_stats.get('mean_latency_us', 0):.2f} μs
- Maximum Jitter: {timing_stats.get('max_jitter_us', 0):.2f} μs
- Average Jitter: {timing_stats.get('avg_jitter_us', 0):.2f} μs

CRITICAL TIMING VIOLATIONS:
{json.dumps(fronthaul_data['timing_violations'][:5], indent=2)}

SAMPLE DU-RU COMMUNICATIONS:
{json.dumps(fronthaul_data['du_ru_communications'][:3], indent=2)}

SAMPLE eCPRI FLOWS:
{json.dumps(fronthaul_data['ecpri_flows'][:3], indent=2)}

ANALYSIS REQUIREMENTS:
Focus specifically on 5G fronthaul DU-RU communication issues:

1. TIMING ANALYSIS:
   - Latency violations (should be < 100μs for 5G fronthaul)
   - Jitter issues affecting synchronization
   - Packet timing irregularities

2. eCPRI PROTOCOL ANALYSIS:
   - Protocol header validation
   - Message type anomalies
   - Payload size inconsistencies

3. DU-RU COMMUNICATION PATTERNS:
   - Communication flow interruptions
   - Missing acknowledgments
   - Sequence number gaps

4. FRONTHAUL SPECIFIC ISSUES:
   - CPRI/eCPRI frame alignment issues
   - IQ data transmission problems
   - Control plane message delays

Provide streaming analysis with immediate findings as you process the data. Format each finding as:

ANOMALY_DETECTED: [TYPE] - [SEVERITY] - [DESCRIPTION]
RECOMMENDATION: [SPECIFIC ACTION NEEDED]

Focus on actionable insights for 5G network engineers. [/INST]</s>"""
        
        return prompt
    
    async def stream_to_websocket(self, message):
        """Stream messages to connected WebSocket clients"""
        if self.websocket_clients:
            disconnected = set()
            for client in self.websocket_clients:
                try:
                    await client.send(json.dumps({
                        'type': 'analysis_update',
                        'message': message,
                        'timestamp': datetime.now().isoformat()
                    }))
                except:
                    disconnected.add(client)
            
            # Remove disconnected clients
            self.websocket_clients -= disconnected
    
    def stream_mistral_analysis(self, prompt, callback):
        """Stream Mistral analysis with real-time output"""
        try:
            cmd = [
                "/tmp/llama.cpp/build/bin/llama-cli",  # Using correct llama.cpp path
                "--model", self.model_path,
                "--prompt", prompt,
                "--n-predict", "2048",
                "--temp", "0.2",
                "--ctx-size", "4096",
                "--stream",  # Enable streaming output
                "--no-display-prompt"
            ]
            
            print("Starting streaming Mistral analysis...")
            
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
                universal_newlines=True
            )
            
            # Stream output line by line
            buffer = ""
            for line in iter(process.stdout.readline, ''):
                if line.strip():
                    buffer += line
                    callback(line.strip())
                    
                    # Check for complete anomaly entries
                    if "ANOMALY_DETECTED:" in buffer:
                        # Process complete anomaly
                        self.process_streaming_anomaly(buffer)
                        buffer = ""
            
            process.wait()
            return buffer
            
        except Exception as e:
            error_msg = f"Error in streaming analysis: {str(e)}"
            callback(error_msg)
            return error_msg
    
    def process_streaming_anomaly(self, text):
        """Process anomaly detected in streaming output"""
        try:
            lines = text.split('\n')
            anomaly_line = None
            recommendation_line = None
            
            for line in lines:
                if "ANOMALY_DETECTED:" in line:
                    anomaly_line = line.replace("ANOMALY_DETECTED:", "").strip()
                elif "RECOMMENDATION:" in line:
                    recommendation_line = line.replace("RECOMMENDATION:", "").strip()
            
            if anomaly_line:
                # Parse anomaly components
                parts = anomaly_line.split(" - ")
                anomaly_type = parts[0] if len(parts) > 0 else "fronthaul"
                severity = parts[1].lower() if len(parts) > 1 else "medium"
                description = parts[2] if len(parts) > 2 else anomaly_line
                
                # Create anomaly record
                anomaly = {
                    'id': str(uuid.uuid4()),
                    'timestamp': datetime.now(),
                    'type': 'fronthaul',
                    'description': description,
                    'severity': severity,
                    'source_file': 'streaming_analysis',
                    'mac_address': None,
                    'ue_id': None,
                    'details': json.dumps({
                        'analysis_type': 'streaming_mistral',
                        'original_type': anomaly_type,
                        'recommendation': recommendation_line or 'Further investigation needed',
                        'detection_method': 'real_time_llm'
                    }),
                    'status': 'open'
                }
                
                # Insert into database
                clickhouse_client.insert_anomaly(anomaly)
                print(f"Streaming anomaly detected: {description}")
        
        except Exception as e:
            print(f"Error processing streaming anomaly: {e}")
    
    def analyze_pcap_streaming(self, pcap_file_path, source_file):
        """Main streaming analysis function"""
        try:
            print(f"Starting streaming analysis of: {pcap_file_path}")
            
            # Load and analyze packets
            packets = rdpcap(pcap_file_path)
            print(f"Loaded {len(packets)} packets for fronthaul analysis")
            
            # Extract fronthaul-specific features
            fronthaul_data = self.extract_fronthaul_features(packets)
            
            # Create specialized prompt
            prompt = self.create_fronthaul_prompt(fronthaul_data, source_file)
            
            # Stream analysis with callback
            analysis_results = []
            
            def streaming_callback(message):
                analysis_results.append(message)
                print(f"STREAM: {message}")
                # Here you can add WebSocket streaming to frontend
                asyncio.create_task(self.stream_to_websocket(message))
            
            # Start streaming analysis
            full_analysis = self.stream_mistral_analysis(prompt, streaming_callback)
            
            # Create session record
            session_id = str(uuid.uuid4())
            session_data = {
                'id': str(uuid.uuid4()),
                'session_id': session_id,
                'start_time': datetime.now(),
                'end_time': datetime.now(),
                'packets_analyzed': len(packets),
                'anomalies_detected': len(fronthaul_data['timing_violations']),
                'source_file': source_file
            }
            
            clickhouse_client.client.insert('sessions', [session_data])
            
            print(f"Streaming analysis complete. Processed {len(packets)} packets.")
            print(f"Found {len(fronthaul_data['timing_violations'])} timing violations")
            
            return len(analysis_results)
            
        except Exception as e:
            print(f"Error in streaming analysis: {str(e)}")
            raise e

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='Streaming PCAP analysis with Mistral for DU-RU fronthaul issues')
    parser.add_argument('--file-id', required=True, help='File ID from database')
    parser.add_argument('--filename', required=True, help='Original filename')
    parser.add_argument('--model-path', default='/tmp/llm_models/mistral-7b-instruct-v0.2.Q4_K_M.gguf',
                        help='Path to Mistral GGUF model')
    
    args = parser.parse_args()
    
    # Read file path from stdin
    pcap_file_path = sys.stdin.read().strip()
    
    analyzer = StreamingMistralAnalyzer(model_path=args.model_path)
    
    try:
        results = analyzer.analyze_pcap_streaming(pcap_file_path, args.filename)
        print(f"SUCCESS: Streaming analysis completed with {results} messages")
        sys.exit(0)
    except Exception as e:
        print(f"ERROR: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()
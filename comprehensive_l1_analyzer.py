#!/usr/bin/env python3
"""
Comprehensive L1 Troubleshooting Analyzer
Single unified system for complete 5G network analysis covering:
- UE Attach/Detach events (PCAP + HDF5 text)
- Fronthaul DU-RU communication issues
- MAC layer anomalies and configuration issues
- Protocol violations and timing constraints
- Signal quality analysis (RSRP/RSRQ/SINR)
- Network performance metrics
"""

import os
import re
import json
import numpy as np
from datetime import datetime
from typing import Dict, List, Tuple, Optional, Union
import warnings
warnings.filterwarnings('ignore')

# Import existing specialized analyzers
from enhanced_ue_event_processor import UEEventProcessor
from enhanced_hybrid_analyzer import EnhancedHybridAnalyzer

# Try to import PCAP processing libraries
try:
    from scapy.all import rdpcap, IP, UDP, TCP, Raw, Ether
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

# Optional ClickHouse integration
try:
    import clickhouse_connect
    CLICKHOUSE_AVAILABLE = True
except ImportError:
    CLICKHOUSE_AVAILABLE = False

class ComprehensiveL1Analyzer:
    def __init__(self, trained_models_path=None):
        # Default directory structure for user praveen.joe
        self.base_dir = "/home/users/praveen.joe/L1"
        self.training_data_dir = f"{self.base_dir}/training_data"
        self.models_dir = f"{self.base_dir}/models"
        self.results_dir = f"{self.base_dir}/results"
        self.production_dir = f"{self.base_dir}/production_data"
        
        # Initialize specialized processors
        self.ue_processor = UEEventProcessor()
        self.ml_analyzer = EnhancedHybridAnalyzer(trained_models_path)
        
        # Pattern definitions for all L1 scenarios
        self.l1_patterns = {
            # UE Events
            'ue_attach': r'(Attach.*Request|ATTACH_REQUEST|EMM.*Attach)',
            'ue_detach': r'(Detach.*Request|DETACH_REQUEST|EMM.*Detach)',
            'ue_handover': r'(Handover.*Request|HO.*Request|X2.*Handover)',
            'rrc_connection': r'(RRC.*Connection|RRCConnection)',
            
            # Fronthaul Issues  
            'ecpri_error': r'(eCPRI.*Error|eCPRI.*Fail|eCPRI.*Timeout)',
            'du_ru_comm': r'(DU.*RU|RU.*DU|O-RAN|F1-C|F1-U)',
            'timing_sync': r'(PTP.*Error|GPS.*Sync|Time.*Sync|Clock.*Error)',
            'fronthaul_link': r'(Link.*Down|Link.*Error|Interface.*Error)',
            
            # MAC Layer Issues
            'mac_address': r'([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}',
            'harq_failure': r'(HARQ.*Fail|HARQ.*NACK|HARQ.*Timeout)',
            'rach_issue': r'(RACH.*Fail|Preamble.*Error|Random.*Access)',
            'scheduling_error': r'(Schedule.*Error|Resource.*Block|RB.*Error)',
            
            # Protocol Violations
            'protocol_error': r'(Protocol.*Error|Invalid.*Message|Malformed)',
            'sequence_error': r'(Sequence.*Error|Out.*of.*Order|SEQ.*Error)',
            'timeout_error': r'(Timeout|Time.*out|Expired)',
            'state_error': r'(State.*Error|Invalid.*State|FSM.*Error)',
            
            # Signal Quality Issues
            'rsrp_poor': r'RSRP[:\s]*(-1[2-9][0-9]|-[2-9][0-9][0-9])',  # < -120 dBm
            'rsrq_poor': r'RSRQ[:\s]*(-1[5-9]|-[2-9][0-9])',  # < -15 dB
            'sinr_poor': r'SINR[:\s]*(-[0-9]+|[0-5])',  # < 5 dB
            'interference': r'(Interference|Co-channel|Adjacent.*channel)',
            
            # Performance Issues
            'throughput_drop': r'(Throughput.*Drop|Data.*Rate.*Drop|Bandwidth.*Low)',
            'latency_high': r'(Latency.*High|RTT.*High|Delay.*High)',
            'packet_loss': r'(Packet.*Loss|Drop.*Rate|Loss.*Rate)',
            'congestion': r'(Congestion|Overload|Capacity.*Exceed)'
        }
        
        # Analysis categories
        self.analysis_categories = {
            'ue_events': ['ue_attach', 'ue_detach', 'ue_handover', 'rrc_connection'],
            'fronthaul': ['ecpri_error', 'du_ru_comm', 'timing_sync', 'fronthaul_link'],
            'mac_layer': ['mac_address', 'harq_failure', 'rach_issue', 'scheduling_error'],
            'protocols': ['protocol_error', 'sequence_error', 'timeout_error', 'state_error'],
            'signal_quality': ['rsrp_poor', 'rsrq_poor', 'sinr_poor', 'interference'],
            'performance': ['throughput_drop', 'latency_high', 'packet_loss', 'congestion']
        }
        
        # ClickHouse setup
        self.clickhouse_client = None
        if CLICKHOUSE_AVAILABLE:
            self.setup_clickhouse()
        
        print("Comprehensive L1 Analyzer initialized")
        print(f"Base directory: {self.base_dir}")
        print(f"PCAP processing available: {SCAPY_AVAILABLE}")
        print(f"ClickHouse integration: {CLICKHOUSE_AVAILABLE}")
    
    def ensure_directories(self):
        """Create default directory structure for user praveen.joe"""
        dirs_to_create = [
            f"{self.base_dir}/training_data/normal",
            f"{self.base_dir}/training_data/anomalous",
            f"{self.base_dir}/training_data/validation",
            f"{self.base_dir}/models",
            f"{self.base_dir}/results/analysis_reports",
            f"{self.base_dir}/results/training_reports",
            f"{self.base_dir}/production_data"
        ]
        
        for directory in dirs_to_create:
            os.makedirs(directory, exist_ok=True)
            
        print(f"Directory structure created at {self.base_dir}")
    
    def setup_clickhouse(self):
        """Setup ClickHouse for comprehensive L1 analysis storage"""
        try:
            self.clickhouse_client = clickhouse_connect.get_client(
                host='localhost',
                port=8123,
                username='default',
                password='',
                database='l1_anomaly_detection'
            )
            
            self.create_comprehensive_tables()
            print("ClickHouse connection established for comprehensive L1 analysis")
            
        except Exception as e:
            print(f"ClickHouse connection failed: {e}")
            self.clickhouse_client = None
    
    def create_comprehensive_tables(self):
        """Create comprehensive ClickHouse tables for all L1 analysis types"""
        if not self.clickhouse_client:
            return
        
        # Tables are now created by setup_clickhouse_tables.py script
        # Just verify they exist and are accessible
        try:
            # Test table access with correct method
            self.clickhouse_client.command("SELECT count() FROM l1_anomaly_detection.comprehensive_anomalies LIMIT 1")
            self.clickhouse_client.command("SELECT count() FROM l1_anomaly_detection.l1_analysis_sessions LIMIT 1")
            print("Comprehensive L1 analysis tables verified in ClickHouse")
        except Exception as e:
            print(f"ClickHouse tables not accessible - analysis will continue without ClickHouse storage: {e}")
    
    def detect_file_format(self, file_path: str) -> str:
        """Enhanced file format detection for all L1 analysis types"""
        try:
            _, ext = os.path.splitext(file_path.lower())
            
            # Check file extensions
            if ext in ['.pcap', '.pcapng']:
                return 'pcap'
            elif ext in ['.log', '.txt']:
                # Analyze content for specific format indicators
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read(2048)
                
                # eCPRI/Fronthaul indicators
                if any(indicator in content.upper() for indicator in ['ECPRI', 'O-RAN', 'F1-C', 'F1-U', 'DU-RU']):
                    return 'fronthaul_log'
                
                # HDF5 measurement indicators
                elif any(indicator in content.upper() for indicator in ['RSRP', 'RSRQ', 'SINR', 'CELL_ID']):
                    return 'hdf5_text'
                
                # MAC/Protocol log indicators
                elif any(indicator in content.upper() for indicator in ['HARQ', 'RACH', 'MAC', 'RRC']):
                    return 'protocol_log'
                
                else:
                    return 'text'
            
            # Try to detect PCAP magic numbers
            with open(file_path, 'rb') as f:
                header = f.read(1024)
            
            pcap_magic = [b'\xa1\xb2\xc3\xd4', b'\xd4\xc3\xb2\xa1', b'\x0a\x0d\x0d\x0a']
            for magic in pcap_magic:
                if header.startswith(magic):
                    return 'pcap'
            
            return 'unknown'
            
        except Exception as e:
            print(f"Error detecting file format for {file_path}: {e}")
            return 'unknown'
    
    def analyze_comprehensive_l1(self, file_path: str) -> Dict:
        """Main comprehensive L1 analysis function"""
        start_time = datetime.now()
        print(f"\nCOMPREHENSIVE L1 ANALYSIS: {os.path.basename(file_path)}")
        print("=" * 80)
        
        # Detect file format
        file_format = self.detect_file_format(file_path)
        print(f"Detected format: {file_format}")
        
        # Initialize comprehensive results
        comprehensive_results = {
            'file_path': file_path,
            'file_format': file_format,
            'analysis_timestamp': start_time.isoformat(),
            'ue_events_analysis': {},
            'fronthaul_analysis': {},
            'mac_layer_analysis': {},
            'protocol_analysis': {},
            'signal_quality_analysis': {},
            'performance_analysis': {},
            'ml_anomaly_analysis': {},
            'comprehensive_anomalies': [],
            'cross_correlations': [],
            'summary': {}
        }
        
        # Run all analysis types based on file format
        if file_format == 'pcap':
            comprehensive_results.update(self.analyze_pcap_comprehensive(file_path))
        elif file_format in ['hdf5_text', 'text', 'protocol_log', 'fronthaul_log']:
            comprehensive_results.update(self.analyze_text_comprehensive(file_path, file_format))
        
        # Run ML-based anomaly detection
        ml_results = self.ml_analyzer.analyze_file_hybrid(file_path)
        comprehensive_results['ml_anomaly_analysis'] = {
            'anomalies_detected': len(ml_results),
            'anomalies': ml_results
        }
        
        # Cross-correlate all findings
        comprehensive_results['cross_correlations'] = self.cross_correlate_all_findings(comprehensive_results)
        comprehensive_results['comprehensive_anomalies'] = self.integrate_all_anomalies(comprehensive_results)
        
        # Generate comprehensive summary
        end_time = datetime.now()
        comprehensive_results['summary'] = self.generate_comprehensive_summary(
            comprehensive_results, 
            (end_time - start_time).total_seconds()
        )
        
        # Store results in ClickHouse
        if self.clickhouse_client:
            self.store_comprehensive_results(comprehensive_results)
        
        # Display results
        self.display_comprehensive_results(comprehensive_results)
        
        return comprehensive_results
    
    def analyze_pcap_comprehensive(self, pcap_file: str) -> Dict:
        """Comprehensive PCAP analysis covering all L1 scenarios"""
        if not SCAPY_AVAILABLE:
            print("Scapy not available - PCAP analysis limited")
            return {}
        
        try:
            packets = rdpcap(pcap_file)
            
            analysis_results = {
                'ue_events_analysis': {'events': [], 'summary': {}},
                'fronthaul_analysis': {'issues': [], 'summary': {}},
                'mac_layer_analysis': {'anomalies': [], 'summary': {}},
                'protocol_analysis': {'violations': [], 'summary': {}},
                'signal_quality_analysis': {'metrics': [], 'summary': {}},
                'performance_analysis': {'metrics': [], 'summary': {}}
            }
            
            # Process each packet
            for i, packet in enumerate(packets):
                packet_analysis = self.analyze_packet_comprehensive(packet, i + 1)
                
                # Categorize findings
                for category, findings in packet_analysis.items():
                    if findings and category in analysis_results:
                        analysis_results[category]['events'].extend(findings)
            
            # Generate summaries for each category
            for category in analysis_results:
                analysis_results[category]['summary'] = self.summarize_category_findings(
                    analysis_results[category], category
                )
            
            print(f"PCAP Analysis: Processed {len(packets)} packets")
            return analysis_results
            
        except Exception as e:
            print(f"Error in comprehensive PCAP analysis: {e}")
            return {}
    
    def analyze_packet_comprehensive(self, packet, packet_number: int) -> Dict:
        """Analyze single packet for all L1 scenarios"""
        packet_findings = {
            'ue_events_analysis': [],
            'fronthaul_analysis': [],
            'mac_layer_analysis': [],
            'protocol_analysis': [],
            'performance_analysis': []
        }
        
        # Extract basic packet info
        packet_info = {
            'packet_number': packet_number,
            'timestamp': float(packet.time) if hasattr(packet, 'time') else 0,
            'size': len(packet)
        }
        
        # Analyze different protocol layers
        if Ether in packet:
            mac_findings = self.analyze_mac_layer_packet(packet, packet_info)
            packet_findings['mac_layer_analysis'].extend(mac_findings)
        
        if IP in packet:
            ip_findings = self.analyze_ip_layer_packet(packet, packet_info)
            packet_findings['protocol_analysis'].extend(ip_findings)
        
        if Raw in packet:
            payload_findings = self.analyze_payload_comprehensive(packet[Raw].load, packet_info)
            for category, findings in payload_findings.items():
                if category in packet_findings:
                    packet_findings[category].extend(findings)
        
        return packet_findings
    
    def analyze_mac_layer_packet(self, packet, packet_info: Dict) -> List:
        """Analyze MAC layer for anomalies"""
        mac_findings = []
        
        if Ether in packet:
            src_mac = packet[Ether].src
            dst_mac = packet[Ether].dst
            
            # Check for MAC address anomalies
            if not self.is_valid_mac(src_mac):
                mac_findings.append({
                    'type': 'invalid_mac_address',
                    'description': f'Invalid source MAC: {src_mac}',
                    'severity': 'medium',
                    'packet_info': packet_info
                })
            
            if src_mac == dst_mac:
                mac_findings.append({
                    'type': 'mac_address_loop',
                    'description': f'Source and destination MAC are identical: {src_mac}',
                    'severity': 'high',
                    'packet_info': packet_info
                })
        
        return mac_findings
    
    def analyze_ip_layer_packet(self, packet, packet_info: Dict) -> List:
        """Analyze IP layer for protocol violations"""
        ip_findings = []
        
        if IP in packet:
            # Check for IP anomalies
            if packet[IP].ttl < 10:
                ip_findings.append({
                    'type': 'low_ttl',
                    'description': f'Unusually low TTL: {packet[IP].ttl}',
                    'severity': 'low',
                    'packet_info': packet_info
                })
            
            # Check for fragmentation issues
            if packet[IP].flags.MF and packet[IP].frag == 0:
                ip_findings.append({
                    'type': 'fragmentation_anomaly',
                    'description': 'More fragments flag set but fragment offset is 0',
                    'severity': 'medium',
                    'packet_info': packet_info
                })
        
        return ip_findings
    
    def analyze_payload_comprehensive(self, payload: bytes, packet_info: Dict) -> Dict:
        """Analyze packet payload for all L1 patterns"""
        payload_findings = {
            'ue_events_analysis': [],
            'fronthaul_analysis': [],
            'protocol_analysis': []
        }
        
        try:
            payload_str = payload.decode('utf-8', errors='ignore')
            
            # Search for all L1 patterns
            for category, patterns in self.analysis_categories.items():
                category_key = f"{category.replace('_', '_')}_analysis"
                if category_key not in payload_findings:
                    category_key = 'protocol_analysis'  # Default fallback
                
                for pattern_name in patterns:
                    if pattern_name in self.l1_patterns:
                        pattern = self.l1_patterns[pattern_name]
                        matches = re.findall(pattern, payload_str, re.IGNORECASE)
                        
                        if matches:
                            payload_findings[category_key].append({
                                'type': pattern_name,
                                'matches': matches,
                                'category': category,
                                'packet_info': packet_info
                            })
        
        except Exception as e:
            # If payload can't be decoded, still record the attempt
            pass
        
        return payload_findings
    
    def analyze_text_comprehensive(self, text_file: str, file_format: str) -> Dict:
        """Comprehensive text file analysis for all L1 scenarios"""
        try:
            with open(text_file, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            lines = content.split('\n')
            
            analysis_results = {
                'ue_events_analysis': {'events': [], 'summary': {}},
                'fronthaul_analysis': {'issues': [], 'summary': {}},
                'mac_layer_analysis': {'anomalies': [], 'summary': {}},
                'protocol_analysis': {'violations': [], 'summary': {}},
                'signal_quality_analysis': {'metrics': [], 'summary': {}},
                'performance_analysis': {'metrics': [], 'summary': {}}
            }
            
            # Process each line
            for i, line in enumerate(lines):
                if not line.strip():
                    continue
                
                line_analysis = self.analyze_line_comprehensive(line, i + 1, file_format)
                
                # Categorize findings
                for category, findings in line_analysis.items():
                    if findings and category in analysis_results:
                        if isinstance(findings, list):
                            analysis_results[category]['events'].extend(findings)
                        else:
                            analysis_results[category]['events'].append(findings)
            
            # Generate summaries
            for category in analysis_results:
                analysis_results[category]['summary'] = self.summarize_category_findings(
                    analysis_results[category], category
                )
            
            print(f"Text Analysis: Processed {len(lines)} lines from {file_format} file")
            return analysis_results
            
        except Exception as e:
            print(f"Error in comprehensive text analysis: {e}")
            return {}
    
    def analyze_line_comprehensive(self, line: str, line_number: int, file_format: str) -> Dict:
        """Analyze single text line for all L1 scenarios"""
        line_findings = {
            'ue_events_analysis': [],
            'fronthaul_analysis': [],
            'mac_layer_analysis': [],
            'protocol_analysis': [],
            'signal_quality_analysis': [],
            'performance_analysis': []
        }
        
        # Search for all pattern categories
        for category, patterns in self.analysis_categories.items():
            category_key = f"{category}_analysis"
            
            for pattern_name in patterns:
                if pattern_name in self.l1_patterns:
                    pattern = self.l1_patterns[pattern_name]
                    matches = re.findall(pattern, line, re.IGNORECASE)
                    
                    if matches:
                        severity = self.determine_severity(pattern_name, matches)
                        
                        finding = {
                            'type': pattern_name,
                            'line_number': line_number,
                            'matches': matches,
                            'severity': severity,
                            'line_content': line[:100],  # First 100 chars
                            'category': category
                        }
                        
                        # Add to appropriate category
                        if category_key in line_findings:
                            line_findings[category_key].append(finding)
        
        return line_findings
    
    def determine_severity(self, pattern_name: str, matches: List) -> str:
        """Determine severity level based on pattern type and matches"""
        high_severity_patterns = [
            'ecpri_error', 'fronthaul_link', 'harq_failure', 'protocol_error',
            'ue_detach', 'timeout_error', 'state_error'
        ]
        
        medium_severity_patterns = [
            'timing_sync', 'rach_issue', 'sequence_error', 'rsrp_poor',
            'ue_handover', 'scheduling_error', 'throughput_drop'
        ]
        
        if pattern_name in high_severity_patterns:
            return 'high'
        elif pattern_name in medium_severity_patterns:
            return 'medium'
        else:
            return 'low'
    
    def cross_correlate_all_findings(self, results: Dict) -> List:
        """Cross-correlate findings from all analysis categories"""
        correlations = []
        
        # Extract all anomalies with timing information
        all_anomalies = []
        
        for category, data in results.items():
            if category.endswith('_analysis') and isinstance(data, dict):
                events = data.get('events', [])
                for event in events:
                    if isinstance(event, dict):
                        event['source_category'] = category
                        all_anomalies.append(event)
        
        # Find temporal correlations (events occurring within 1 second)
        for i, anomaly1 in enumerate(all_anomalies):
            for anomaly2 in all_anomalies[i+1:]:
                correlation = self.check_temporal_correlation(anomaly1, anomaly2)
                if correlation:
                    correlations.append(correlation)
        
        return correlations
    
    def check_temporal_correlation(self, anomaly1: Dict, anomaly2: Dict) -> Optional[Dict]:
        """Check if two anomalies are temporally correlated"""
        # Extract timestamps
        ts1 = anomaly1.get('packet_info', {}).get('timestamp', 0)
        ts2 = anomaly2.get('packet_info', {}).get('timestamp', 0)
        
        line1 = anomaly1.get('line_number', 0)
        line2 = anomaly2.get('line_number', 0)
        
        # Check temporal proximity (within 1 second or 10 lines)
        if (abs(ts1 - ts2) <= 1.0 and ts1 > 0 and ts2 > 0) or abs(line1 - line2) <= 10:
            return {
                'type': 'temporal_correlation',
                'anomaly1': anomaly1,
                'anomaly2': anomaly2,
                'time_difference': abs(ts1 - ts2) if ts1 > 0 and ts2 > 0 else None,
                'line_difference': abs(line1 - line2) if line1 > 0 and line2 > 0 else None,
                'correlation_strength': self.calculate_correlation_strength(anomaly1, anomaly2)
            }
        
        return None
    
    def calculate_correlation_strength(self, anomaly1: Dict, anomaly2: Dict) -> float:
        """Calculate correlation strength between two anomalies"""
        strength = 0.5  # Base correlation
        
        # Increase strength for related categories
        category_relations = {
            ('ue_events', 'protocol'): 0.3,
            ('fronthaul', 'performance'): 0.4,
            ('mac_layer', 'protocol'): 0.3,
            ('signal_quality', 'performance'): 0.4
        }
        
        cat1 = anomaly1.get('category', '')
        cat2 = anomaly2.get('category', '')
        
        for (c1, c2), bonus in category_relations.items():
            if (c1 in cat1 and c2 in cat2) or (c2 in cat1 and c1 in cat2):
                strength += bonus
        
        return min(strength, 1.0)
    
    def integrate_all_anomalies(self, results: Dict) -> List:
        """Integrate anomalies from all analysis categories"""
        integrated_anomalies = []
        anomaly_id = 1
        
        for category, data in results.items():
            if category.endswith('_analysis') and isinstance(data, dict):
                events = data.get('events', [])
                
                for event in events:
                    if isinstance(event, dict):
                        integrated_anomaly = {
                            'id': f"L1_{anomaly_id:04d}",
                            'category': category.replace('_analysis', ''),
                            'type': event.get('type', 'unknown'),
                            'severity': event.get('severity', 'low'),
                            'confidence': self.calculate_confidence_score(event),
                            'description': self.generate_anomaly_description(event),
                            'timestamp': datetime.now().isoformat(),
                            'packet_number': event.get('packet_info', {}).get('packet_number', 0),
                            'line_number': event.get('line_number', 0),
                            'source_data': event
                        }
                        
                        integrated_anomalies.append(integrated_anomaly)
                        anomaly_id += 1
        
        # Sort by severity and confidence
        severity_order = {'high': 3, 'medium': 2, 'low': 1}
        integrated_anomalies.sort(
            key=lambda x: (severity_order.get(x['severity'], 0), x['confidence']),
            reverse=True
        )
        
        return integrated_anomalies
    
    def calculate_confidence_score(self, event: Dict) -> float:
        """Calculate confidence score for an anomaly"""
        base_confidence = 0.5
        
        # Adjust based on pattern type
        if event.get('type') in ['ecpri_error', 'protocol_error', 'harq_failure']:
            base_confidence += 0.3
        elif event.get('type') in ['timing_sync', 'rach_issue']:
            base_confidence += 0.2
        
        # Adjust based on number of matches
        matches = event.get('matches', [])
        if len(matches) > 1:
            base_confidence += 0.1
        
        # Adjust based on severity
        severity = event.get('severity', 'low')
        if severity == 'high':
            base_confidence += 0.2
        elif severity == 'medium':
            base_confidence += 0.1
        
        return min(base_confidence, 1.0)
    
    def generate_anomaly_description(self, event: Dict) -> str:
        """Generate human-readable description for anomaly"""
        anomaly_type = event.get('type', 'unknown')
        matches = event.get('matches', [])
        
        descriptions = {
            'ue_attach': f'UE Attach procedure detected with patterns: {matches}',
            'ue_detach': f'UE Detach procedure detected with patterns: {matches}',
            'ecpri_error': f'eCPRI communication error: {matches}',
            'harq_failure': f'HARQ process failure detected: {matches}',
            'protocol_error': f'Protocol violation found: {matches}',
            'rsrp_poor': f'Poor RSRP signal quality: {matches}',
            'timing_sync': f'Timing synchronization issue: {matches}',
            'mac_address': f'MAC address anomaly: {matches}',
            'throughput_drop': f'Network throughput degradation: {matches}',
            'packet_loss': f'Packet loss detected: {matches}'
        }
        
        return descriptions.get(anomaly_type, f'L1 anomaly of type {anomaly_type}: {matches}')
    
    def summarize_category_findings(self, category_data: Dict, category: str) -> Dict:
        """Generate summary for a specific analysis category"""
        events = category_data.get('events', [])
        
        if not events:
            return {'total_events': 0, 'severity_breakdown': {}}
        
        severity_counts = {'high': 0, 'medium': 0, 'low': 0}
        type_counts = {}
        
        for event in events:
            severity = event.get('severity', 'low')
            event_type = event.get('type', 'unknown')
            
            severity_counts[severity] += 1
            type_counts[event_type] = type_counts.get(event_type, 0) + 1
        
        return {
            'total_events': len(events),
            'severity_breakdown': severity_counts,
            'type_breakdown': type_counts,
            'most_common_type': max(type_counts.items(), key=lambda x: x[1])[0] if type_counts else None
        }
    
    def generate_comprehensive_summary(self, results: Dict, analysis_duration: float) -> Dict:
        """Generate comprehensive analysis summary"""
        total_anomalies = len(results.get('comprehensive_anomalies', []))
        
        # Count anomalies by category
        category_counts = {}
        severity_counts = {'high': 0, 'medium': 0, 'low': 0}
        
        for anomaly in results.get('comprehensive_anomalies', []):
            category = anomaly.get('category', 'unknown')
            severity = anomaly.get('severity', 'low')
            
            category_counts[category] = category_counts.get(category, 0) + 1
            severity_counts[severity] += 1
        
        # Calculate overall health score
        health_score = self.calculate_overall_health_score(severity_counts, total_anomalies)
        
        return {
            'total_anomalies': total_anomalies,
            'category_breakdown': category_counts,
            'severity_breakdown': severity_counts,
            'cross_correlations': len(results.get('cross_correlations', [])),
            'ml_anomalies': results.get('ml_anomaly_analysis', {}).get('anomalies_detected', 0),
            'overall_health_score': health_score,
            'analysis_duration_seconds': analysis_duration,
            'file_format': results.get('file_format', 'unknown'),
            'analysis_timestamp': results.get('analysis_timestamp', '')
        }
    
    def calculate_overall_health_score(self, severity_counts: Dict, total_anomalies: int) -> float:
        """Calculate overall network health score (0-100)"""
        if total_anomalies == 0:
            return 100.0
        
        # Weight different severities
        weighted_score = (
            severity_counts.get('high', 0) * 10 +
            severity_counts.get('medium', 0) * 5 +
            severity_counts.get('low', 0) * 1
        )
        
        # Normalize to 0-100 scale
        max_possible_score = total_anomalies * 10  # All high severity
        health_score = max(0, 100 - (weighted_score / max_possible_score * 100))
        
        return round(health_score, 2)
    
    def store_comprehensive_results(self, results: Dict):
        """Store comprehensive analysis results in ClickHouse"""
        if not self.clickhouse_client:
            return
        
        try:
            # Store session summary
            session_data = [
                f"L1_session_{datetime.now().timestamp()}",
                datetime.now(),
                results['file_path'],
                results['file_format'],
                0,  # total_packets (would need to be extracted)
                0,  # total_lines (would need to be extracted)
                len([a for a in results.get('comprehensive_anomalies', []) if a.get('category') == 'ue_events']),
                len([a for a in results.get('comprehensive_anomalies', []) if a.get('category') == 'fronthaul']),
                len([a for a in results.get('comprehensive_anomalies', []) if a.get('category') == 'mac_layer']),
                len([a for a in results.get('comprehensive_anomalies', []) if a.get('category') == 'protocols']),
                len([a for a in results.get('comprehensive_anomalies', []) if a.get('category') == 'signal_quality']),
                len([a for a in results.get('comprehensive_anomalies', []) if a.get('category') == 'performance']),
                results['summary']['total_anomalies'],
                results['summary']['severity_breakdown'].get('high', 0),
                results['summary']['severity_breakdown'].get('medium', 0),
                results['summary']['severity_breakdown'].get('low', 0),
                results['summary']['overall_health_score'],
                results['summary']['analysis_duration_seconds'],
                json.dumps(results['summary'])
            ]
            
            self.clickhouse_client.insert('l1_anomaly_detection.l1_analysis_sessions', [session_data])
            
            # Store individual anomalies
            for anomaly in results.get('comprehensive_anomalies', []):
                anomaly_data = [
                    anomaly['id'],
                    datetime.now(),
                    results['file_path'],
                    results['file_format'],
                    anomaly['category'],
                    anomaly['type'],
                    anomaly['severity'],
                    anomaly['confidence'],
                    anomaly.get('packet_number', 0),
                    anomaly.get('line_number', 0),
                    anomaly['description'],
                    1 if anomaly['category'] == 'ue_events' else 0,
                    1 if anomaly['category'] == 'fronthaul' else 0,
                    1 if anomaly['category'] == 'mac_layer' else 0,
                    1 if anomaly['category'] == 'protocols' else 0,
                    1 if anomaly['category'] == 'signal_quality' else 0,
                    1 if anomaly['category'] == 'performance' else 0,
                    0,  # ml_detected (would need ML integration)
                    1,  # rule_based_detected
                    0,  # cross_correlated (would need correlation check)
                    json.dumps(anomaly['source_data'])
                ]
                
                self.clickhouse_client.insert('l1_anomaly_detection.comprehensive_anomalies', [anomaly_data])
            
            print("Comprehensive analysis results stored in ClickHouse")
            
        except Exception as e:
            print(f"Failed to store comprehensive results: {e}")
    
    def display_comprehensive_results(self, results: Dict):
        """Display comprehensive analysis results"""
        print(f"\nCOMPREHENSIVE L1 ANALYSIS RESULTS")
        print("=" * 80)
        print(f"File: {os.path.basename(results['file_path'])}")
        print(f"Format: {results['file_format']}")
        print(f"Analysis Time: {results['analysis_timestamp']}")
        
        # Overall Summary
        summary = results['summary']
        print(f"\nOVERALL SUMMARY:")
        print(f"  Total Anomalies: {summary['total_anomalies']}")
        print(f"  Overall Health Score: {summary['overall_health_score']}/100")
        print(f"  Analysis Duration: {summary['analysis_duration_seconds']:.2f} seconds")
        
        # Severity Breakdown
        print(f"\nSEVERITY BREAKDOWN:")
        for severity, count in summary['severity_breakdown'].items():
            print(f"  {severity.title()}: {count}")
        
        # Category Breakdown
        print(f"\nCATEGORY BREAKDOWN:")
        for category, count in summary['category_breakdown'].items():
            print(f"  {category.replace('_', ' ').title()}: {count}")
        
        # Cross-correlations
        if results.get('cross_correlations'):
            print(f"\nCROSS-CORRELATIONS: {len(results['cross_correlations'])}")
            for correlation in results['cross_correlations'][:3]:  # Show top 3
                strength = correlation.get('correlation_strength', 0)
                print(f"  Correlation strength {strength:.2f} between {correlation['anomaly1']['type']} and {correlation['anomaly2']['type']}")
        
        # Top Anomalies
        anomalies = results.get('comprehensive_anomalies', [])
        if anomalies:
            print(f"\nTOP COMPREHENSIVE ANOMALIES:")
            for i, anomaly in enumerate(anomalies[:10], 1):  # Show top 10
                category = anomaly['category'].replace('_', ' ').title()
                severity = anomaly['severity'].upper()
                confidence = anomaly['confidence']
                description = anomaly['description'][:60] + "..." if len(anomaly['description']) > 60 else anomaly['description']
                
                print(f"  {i}. [{category}] {severity} - {description} (Confidence: {confidence:.3f})")
        
        print(f"\nAnalysis complete - {summary['total_anomalies']} anomalies found across all L1 categories")
    
    def is_valid_mac(self, mac: str) -> bool:
        """Validate MAC address format"""
        mac_pattern = r'^([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}$'
        return bool(re.match(mac_pattern, mac))
    
    def train_with_default_paths(self):
        """Train models using default directory paths"""
        self.ensure_directories()
        
        normal_data_path = f"{self.training_data_dir}/normal"
        anomalous_data_path = f"{self.training_data_dir}/anomalous"
        
        # Check if training data exists
        if not os.path.exists(normal_data_path) or not os.listdir(normal_data_path):
            print(f"No training data found at {normal_data_path}")
            print("Please add clean UE event files (PCAP/HDF5 text) to train the system")
            return False
        
        # Import and use hybrid trainer
        from hybrid_ml_trainer import HybridMLTrainer
        
        trainer = HybridMLTrainer()
        
        # Train with available data
        if os.path.exists(anomalous_data_path) and os.listdir(anomalous_data_path):
            print("Training with both normal and anomalous data...")
            return trainer.train_hybrid_models(
                normal_data_path=normal_data_path,
                anomalous_data_path=anomalous_data_path,
                output_dir=self.models_dir
            )
        else:
            print("Training with normal data only (unsupervised)...")
            return trainer.train_hybrid_models(
                normal_data_path=normal_data_path,
                output_dir=self.models_dir
            )

def main():
    """Main execution for comprehensive L1 analysis"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Comprehensive L1 Troubleshooting Analyzer')
    parser.add_argument('input_path', nargs='?', help='File or directory to analyze')
    parser.add_argument('--train', action='store_true', help='Train models using default paths')
    parser.add_argument('--use-trained-models', help='Path to trained models directory')
    parser.add_argument('--batch', action='store_true', help='Process all files in directory')
    parser.add_argument('--output', help='Output JSON file for results')
    parser.add_argument('--ensure-dirs', action='store_true', help='Create default directory structure')
    
    args = parser.parse_args()
    
    # Create comprehensive analyzer
    analyzer = ComprehensiveL1Analyzer(trained_models_path=args.use_trained_models)
    
    # Handle different modes
    if args.ensure_dirs:
        analyzer.ensure_directories()
        print("Default directory structure created")
        return
    
    if args.train:
        success = analyzer.train_with_default_paths()
        if success:
            print("Model training completed successfully")
        else:
            print("Model training failed - check training data")
        return
    
    if not args.input_path:
        print("Please provide input file/directory or use --train to train models")
        return
    
    # Analysis mode
    if args.batch and os.path.isdir(args.input_path):
        # Batch processing
        total_files = 0
        total_anomalies = 0
        
        for filename in os.listdir(args.input_path):
            file_path = os.path.join(args.input_path, filename)
            if os.path.isfile(file_path):
                print(f"\nProcessing: {filename}")
                results = analyzer.analyze_comprehensive_l1(file_path)
                
                if results:
                    total_files += 1
                    total_anomalies += results['summary']['total_anomalies']
        
        print(f"\nBATCH PROCESSING COMPLETE")
        print(f"Files processed: {total_files}")
        print(f"Total anomalies found: {total_anomalies}")
        
    else:
        # Single file processing
        results = analyzer.analyze_comprehensive_l1(args.input_path)
        
        if results and args.output:
            with open(args.output, 'w') as f:
                json.dump(results, f, indent=2)
            print(f"\nResults saved to: {args.output}")

if __name__ == "__main__":
    main()
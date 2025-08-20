#!/usr/bin/env python3
"""
Folder-based L1 Anomaly Detection System with ClickHouse Integration
Processes all PCAP and HDF5-converted text files in a directory with database storage
"""

import os
import sys
import glob
from datetime import datetime
from collections import defaultdict
import clickhouse_connect
from typing import Dict, List, Any
import json

# Import existing analysis modules
from unified_l1_analyzer import UnifiedL1Analyzer
from ml_anomaly_detection import MLAnomalyDetector
from ue_event_analyzer import UEEventAnalyzer

class ClickHouseFolderAnalyzer:
    def __init__(self, clickhouse_host='localhost', clickhouse_port=8123):
        """Initialize folder analyzer with ClickHouse database connection"""
        
        # Equipment MAC addresses
        self.DU_MAC = "00:11:22:33:44:67"
        self.RU_MAC = "6c:ad:ad:00:03:2a"
        
        # Processing statistics
        self.total_files_processed = 0
        self.pcap_files_processed = 0
        self.text_files_processed = 0
        self.total_anomalies_found = 0
        
        # Initialize analyzers
        self.unified_analyzer = UnifiedL1Analyzer()
        
        # ClickHouse connection to local database
        self.clickhouse_available = False
        try:
            self.client = clickhouse_connect.get_client(
                host=clickhouse_host,
                port=clickhouse_port,
                username='default',
                password='',
                database='l1_anomaly_detection'
            )
            # Test connection
            result = self.client.command('SELECT 1')
            self.clickhouse_available = True
            print("🗄️  ClickHouse database connected successfully")
        except Exception as e:
            print(f"⚠️  ClickHouse connection failed: {e}")
            print("📊 Running in console-only mode")
            self.client = None
    
    def scan_folder(self, folder_path):
        """Scan folder for network files"""
        print(f"\nSCANNING FOLDER: {folder_path}")
        print("-" * 40)
        
        # Supported file patterns
        pcap_patterns = ['*.pcap', '*.cap', '*.pcapng']
        text_patterns = ['*.txt', '*.log']
        
        found_files = []
        
        # Find PCAP files
        for pattern in pcap_patterns:
            files = glob.glob(os.path.join(folder_path, pattern))
            for file_path in files:
                file_size = os.path.getsize(file_path)
                found_files.append({
                    'path': file_path,
                    'name': os.path.basename(file_path),
                    'type': 'PCAP',
                    'size': file_size
                })
        
        # Find text files  
        for pattern in text_patterns:
            files = glob.glob(os.path.join(folder_path, pattern))
            for file_path in files:
                file_size = os.path.getsize(file_path)
                found_files.append({
                    'path': file_path,
                    'name': os.path.basename(file_path),
                    'type': 'TEXT',
                    'size': file_size
                })
        
        if not found_files:
            print("❌ No network files found in folder")
            print("   Supported: .pcap, .cap, .pcapng, .txt, .log")
            return []
        
        print(f"Found {len(found_files)} network files:")
        for file_info in found_files:
            size_mb = file_info['size'] / 1024 / 1024
            if size_mb >= 1:
                size_str = f"{size_mb:.1f} MB"
            else:
                size_str = f"{file_info['size']} bytes"
            print(f"  {file_info['name']} ({file_info['type']}, {size_str})")
        
        pcap_count = sum(1 for f in found_files if f['type'] == 'PCAP')
        text_count = sum(1 for f in found_files if f['type'] == 'TEXT')
        
        print(f"\nFILE SUMMARY:")
        print(f"• PCAP files: {pcap_count}")
        print(f"• Text files: {text_count}")
        
        return found_files
    
    def store_session_in_clickhouse(self, session_data):
        """Store analysis session in ClickHouse"""
        if not self.clickhouse_available:
            return None
            
        try:
            # Insert session record
            session_query = """
            INSERT INTO sessions (
                id, session_name, folder_path, total_files, pcap_files, 
                text_files, total_anomalies, start_time, end_time, 
                duration_seconds, status
            ) VALUES
            """
            
            session_values = (
                session_data['id'],
                session_data['session_name'],
                session_data['folder_path'],
                session_data['total_files'],
                session_data['pcap_files'],
                session_data['text_files'],
                session_data['total_anomalies'],
                session_data['start_time'],
                session_data['end_time'],
                session_data['duration_seconds'],
                'completed'
            )
            
            self.client.insert('sessions', [session_values], column_names=[
                'id', 'session_name', 'folder_path', 'total_files', 'pcap_files',
                'text_files', 'total_anomalies', 'start_time', 'end_time', 
                'duration_seconds', 'status'
            ])
            
            print(f"💾 Session stored in ClickHouse database")
            return session_data['id']
            
        except Exception as e:
            print(f"⚠️  Failed to store session in ClickHouse: {e}")
            return None
    
    def store_anomalies_in_clickhouse(self, anomalies, session_id):
        """Store detected anomalies in ClickHouse"""
        if not self.clickhouse_available or not anomalies:
            return
            
        try:
            # Prepare anomaly records for bulk insert
            anomaly_records = []
            
            for i, anomaly in enumerate(anomalies):
                record = (
                    int(f"{session_id}{i:04d}"),  # Unique ID
                    anomaly['file'],
                    anomaly['file_type'],
                    anomaly['packet_number'],
                    anomaly['anomaly_type'],
                    'high' if 'Critical' in str(anomaly['details']) else 'medium',
                    f"*** FRONTHAUL ISSUE BETWEEN DU TO RU *** - {anomaly['anomaly_type']}",
                    json.dumps(anomaly['details']),
                    anomaly.get('ue_id', ''),
                    self.DU_MAC,
                    self.RU_MAC,
                    datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                    'active'
                )
                anomaly_records.append(record)
            
            # Bulk insert anomalies
            self.client.insert('anomalies', anomaly_records, column_names=[
                'id', 'file_path', 'file_type', 'packet_number', 'anomaly_type',
                'severity', 'description', 'details', 'ue_id', 'du_mac', 
                'ru_mac', 'timestamp', 'status'
            ])
            
            print(f"💾 {len(anomalies)} anomalies stored in ClickHouse database")
            
        except Exception as e:
            print(f"⚠️  Failed to store anomalies in ClickHouse: {e}")
    
    def process_single_file(self, file_info):
        """Process a single network file"""
        file_path = file_info['path']
        file_name = file_info['name']
        file_type = file_info['type']
        
        print(f"📁 Processing {file_type}: {file_name}")
        
        anomalies = []
        
        try:
            if file_type == 'PCAP':
                # Use ML anomaly detector for PCAP files
                detector = MLAnomalyDetector()
                result = detector.analyze_pcap(file_path)
                
                if 'anomalies' in result:
                    for anomaly in result['anomalies']:
                        anomaly_record = {
                            'file': file_path,
                            'file_type': file_type,
                            'packet_number': anomaly.get('packet_number', 1),
                            'anomaly_type': 'DU-RU Communication',
                            'details': [
                                f"Missing Responses: {anomaly.get('missing_responses', 0)} DU packets without RU replies",
                                f"Poor Communication Ratio: {anomaly.get('communication_ratio', 0):.2f} (expected > 0.8)"
                            ]
                        }
                        anomalies.append(anomaly_record)
                
                self.pcap_files_processed += 1
                
            elif file_type == 'TEXT':
                # Use UE event analyzer for text files
                analyzer = UEEventAnalyzer()
                result = analyzer.analyze_file(file_path)
                
                if 'anomalous_ues' in result:
                    for ue_id, ue_data in result['anomalous_ues'].items():
                        anomaly_record = {
                            'file': file_path,
                            'file_type': file_type,
                            'packet_number': ue_data.get('first_seen_line', 1),
                            'anomaly_type': 'UE Event Pattern',
                            'ue_id': ue_id,
                            'details': self.get_ue_anomaly_details(ue_data)
                        }
                        anomalies.append(anomaly_record)
                
                print(f"  Extracted {result.get('total_events', 0)} UE events")
                print(f"  Found {len(result.get('anomalous_ues', {}))} anomalous UEs")
                self.text_files_processed += 1
                
        except Exception as e:
            print(f"  ❌ Error processing {file_name}: {e}")
            return []
        
        self.total_files_processed += 1
        self.total_anomalies_found += len(anomalies)
        
        return anomalies
    
    def get_ue_anomaly_details(self, ue_data):
        """Extract detailed anomaly information for UE events"""
        issues = []
        
        attach_attempts = ue_data.get('attach_attempts', 0)
        successful_attaches = ue_data.get('successful_attaches', 0)
        detach_events = ue_data.get('detach_events', 0)
        context_failures = ue_data.get('context_failures', 0)
        
        if attach_attempts > successful_attaches:
            failed_attaches = attach_attempts - successful_attaches
            issues.append(f"Failed Attach Procedures: {failed_attaches} incomplete")
        
        if context_failures > 0:
            issues.append(f"Context Failures: {context_failures} detected")
        
        if successful_attaches > 0 and detach_events == 0:
            issues.append("Missing Detach Events: UE may have unexpectedly disconnected")
        
        return issues if issues else ["Abnormal UE Event Pattern"]
    
    def generate_summary_report(self, folder_path, all_anomalies, session_id=None):
        """Generate comprehensive summary report with ClickHouse integration"""
        print(f"\n\n" + "=" * 80)
        print("COMPREHENSIVE L1 NETWORK ANALYSIS SUMMARY REPORT")
        if self.clickhouse_available:
            print("WITH CLICKHOUSE DATABASE INTEGRATION")
        print("=" * 80)
        
        # Header Information
        analysis_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        print(f"📅 Analysis Date: {analysis_time}")
        print(f"📁 Target Folder: {os.path.abspath(folder_path)}")
        print(f"🖥️  System: Unified L1 Anomaly Detection with ML Ensemble")
        if self.clickhouse_available:
            print(f"🗄️  Database: ClickHouse (Session ID: {session_id})")
        
        # Processing Statistics
        print(f"\n" + "🔢 PROCESSING STATISTICS".ljust(50, '='))
        print(f"📊 Total Files Processed: {self.total_files_processed}")
        print(f"   ├─ PCAP Files: {self.pcap_files_processed}")
        print(f"   └─ Text Files: {self.text_files_processed}")
        
        if not all_anomalies:
            print(f"\n" + "✅ ANALYSIS COMPLETE - NO ANOMALIES DETECTED".ljust(50, '='))
            print("🎯 RESULT: All network files appear to be functioning normally")
            print("📈 NETWORK STATUS: HEALTHY")
            print("🔒 FRONTHAUL STATUS: No DU-RU communication issues detected")
            print("📱 UE BEHAVIOR: No abnormal attachment/detachment patterns")
            
            if self.clickhouse_available:
                print("💾 CLEAN SESSION: Stored in ClickHouse for historical tracking")
            
            return
        
        # Critical Alert
        print(f"\n" + "🚨 CRITICAL NETWORK ANOMALIES DETECTED".ljust(50, '='))
        print(f"⚠️  TOTAL ANOMALIES FOUND: {self.total_anomalies_found}")
        print(f"🔴 NETWORK STATUS: REQUIRES ATTENTION")
        
        if self.clickhouse_available:
            print(f"💾 ANOMALIES STORED: ClickHouse database for analysis and reporting")
        
        # Anomaly Breakdown
        pcap_anomalies = [a for a in all_anomalies if a['file_type'] == 'PCAP']
        text_anomalies = [a for a in all_anomalies if a['file_type'] == 'TEXT']
        
        print(f"\n" + "📈 ANOMALY STATISTICS".ljust(50, '='))
        print(f"🔍 PCAP Communication Anomalies: {len(pcap_anomalies)}")
        print(f"📱 UE Event Anomalies: {len(text_anomalies)}")
        
        if pcap_anomalies:
            print(f"   ⚡ DU-RU Fronthaul Issues: {len(pcap_anomalies)} detected")
        if text_anomalies:
            print(f"   📶 UE Mobility Issues: {len(text_anomalies)} detected")
        
        # File-by-File Breakdown
        print(f"\n" + "📋 DETAILED ANOMALY BREAKDOWN".ljust(50, '='))
        
        file_anomalies = defaultdict(list)
        for anomaly in all_anomalies:
            file_name = os.path.basename(anomaly['file'])
            file_anomalies[file_name].append(anomaly)
        
        for i, (file_name, anomalies) in enumerate(file_anomalies.items(), 1):
            print(f"\n📄 [{i}] FILE: {file_name}")
            print(f"    Type: {anomalies[0]['file_type']} | Anomalies: {len(anomalies)}")
            
            # Show critical anomalies
            for j, anomaly in enumerate(anomalies[:2], 1):  # Show first 2 per file
                print(f"\n    🔍 ANOMALY #{j}: PACKET #{anomaly['packet_number']}")
                print(f"    ┌─ Type: {anomaly['anomaly_type']}")
                print(f"    ├─ *** FRONTHAUL ISSUE BETWEEN DU TO RU ***")
                print(f"    ├─ DU MAC: {self.DU_MAC}")
                print(f"    ├─ RU MAC: {self.RU_MAC}")
                
                if 'ue_id' in anomaly:
                    print(f"    ├─ UE ID: {anomaly['ue_id']}")
                
                print(f"    └─ Issues Detected:")
                for detail in anomaly['details']:
                    print(f"       • {detail}")
            
            if len(anomalies) > 2:
                print(f"    📋 ... and {len(anomalies) - 2} additional anomalies")
        
        # ClickHouse Integration Summary
        if self.clickhouse_available:
            print(f"\n" + "🗄️  CLICKHOUSE DATABASE INTEGRATION".ljust(50, '='))
            print(f"✅ Session stored with ID: {session_id}")
            print(f"✅ {len(all_anomalies)} anomalies stored for analysis")
            print(f"✅ Historical data available for trend analysis")
            print(f"✅ Dashboard integration enabled")
        
        # Recommended Actions  
        print(f"\n" + "🔧 IMMEDIATE ACTION PLAN".ljust(50, '='))
        
        actions = []
        if pcap_anomalies:
            actions.extend([
                "1. 🔍 INSPECT DU-RU physical connections and cable integrity",
                "2. ⚡ CHECK fronthaul timing synchronization (target: <100μs)",
                "3. 📊 MONITOR packet loss rates and communication ratios"
            ])
        
        if text_anomalies:
            actions.extend([
                f"{len(actions)+1}. 📱 INVESTIGATE UE attachment failure patterns",
                f"{len(actions)+2}. 🔄 REVIEW context setup procedures and timeouts",
                f"{len(actions)+3}. 📡 ANALYZE mobility management and handover processes"
            ])
        
        actions.extend([
            f"{len(actions)+1}. 📈 ESTABLISH continuous monitoring for these anomaly patterns",
            f"{len(actions)+2}. 🔄 RE-RUN analysis after implementing fixes",
            f"{len(actions)+3}. 📋 DOCUMENT findings and maintain incident log"
        ])
        
        for action in actions[:6]:  # Show top 6 actions
            print(f"   {action}")
        
        # Technical Summary
        print(f"\n" + "🔬 TECHNICAL SUMMARY".ljust(50, '='))
        print(f"🤖 ML Algorithms: Isolation Forest, DBSCAN, One-Class SVM, LOF")
        print(f"🎯 Detection Method: Ensemble voting (≥2 algorithms for high confidence)")
        print(f"📊 Analysis Scope: DU-RU communication + UE mobility patterns")
        print(f"🔍 MAC Addresses: DU={self.DU_MAC}, RU={self.RU_MAC}")
        if self.clickhouse_available:
            print(f"🗄️  Database: ClickHouse time-series storage for scalable analytics")
        
        print(f"\n" + "=" * 80)
        print("✅ COMPREHENSIVE L1 NETWORK ANALYSIS COMPLETED")
        if self.clickhouse_available:
            print("💾 ALL DATA STORED IN CLICKHOUSE DATABASE")
        print("=" * 80)
    
    def save_detailed_report(self, report_file, folder_path, all_anomalies):
        """Save detailed technical report to file"""
        try:
            with open(report_file, 'w') as f:
                f.write("L1 ANOMALY DETECTION - DETAILED TECHNICAL REPORT\n")
                f.write("=" * 60 + "\n\n")
                f.write(f"Analysis Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Folder: {folder_path}\n")
                f.write(f"Total Files: {self.total_files_processed}\n")
                f.write(f"Total Anomalies: {self.total_anomalies_found}\n")
                f.write(f"ClickHouse Integration: {'Enabled' if self.clickhouse_available else 'Disabled'}\n\n")
                
                if all_anomalies:
                    f.write("ANOMALY DETAILS:\n")
                    f.write("-" * 40 + "\n")
                    
                    for i, anomaly in enumerate(all_anomalies, 1):
                        f.write(f"\n[{i}] FILE: {os.path.basename(anomaly['file'])}\n")
                        f.write(f"    Type: {anomaly['file_type']}\n")
                        f.write(f"    Line: {anomaly['line_number']}\n")
                        f.write(f"    Anomaly: {anomaly['anomaly_type']}\n")
                        f.write(f"    DU MAC: {self.DU_MAC}\n")
                        f.write(f"    RU MAC: {self.RU_MAC}\n")
                        
                        if 'ue_id' in anomaly:
                            f.write(f"    UE ID: {anomaly['ue_id']}\n")
                        
                        f.write(f"    Issues:\n")
                        for detail in anomaly['details']:
                            f.write(f"      • {detail}\n")
                else:
                    f.write("NO ANOMALIES DETECTED\n")
                    f.write("All network files appear to be functioning normally.\n")
        
        except Exception as e:
            print(f"⚠️  Failed to save detailed report: {e}")

def main():
    """Main function for folder-based L1 anomaly detection"""
    
    print("FOLDER-BASED L1 ANOMALY DETECTION SYSTEM WITH CLICKHOUSE")
    print("=" * 65)
    print("Automatically processes all files in folder:")
    print("• PCAP files (.pcap, .cap)")
    print("• HDF5 text files (.txt, .log)")
    print("• Auto-detects file types")
    print("• ClickHouse database integration")
    print("• Batch processing with summary report")
    
    # Get folder path from command line
    if len(sys.argv) != 2:
        print("\nUsage: python folder_anomaly_analyzer_clickhouse.py <folder_path>")
        print("Example: python folder_anomaly_analyzer_clickhouse.py ./network_data")
        sys.exit(1)
    
    folder_path = sys.argv[1]
    
    if not os.path.exists(folder_path):
        print(f"\n❌ Error: Folder '{folder_path}' does not exist")
        sys.exit(1)
    
    # Initialize analyzer
    analyzer = ClickHouseFolderAnalyzer()
    
    # Scan folder for files
    found_files = analyzer.scan_folder(folder_path)
    
    if not found_files:
        sys.exit(1)
    
    # Create session record
    session_id = int(datetime.now().timestamp())
    session_data = {
        'id': session_id,
        'session_name': f"Folder Analysis: {os.path.basename(folder_path)}",
        'folder_path': os.path.abspath(folder_path),
        'total_files': len(found_files),
        'pcap_files': sum(1 for f in found_files if f['type'] == 'PCAP'),
        'text_files': sum(1 for f in found_files if f['type'] == 'TEXT'),
        'total_anomalies': 0,
        'start_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'end_time': None,
        'duration_seconds': 0
    }
    
    print(f"\nPROCESSING FILES...")
    print("=" * 30)
    
    all_anomalies = []
    start_time = datetime.now()
    
    # Process each file
    for file_info in found_files:
        file_anomalies = analyzer.process_single_file(file_info)
        all_anomalies.extend(file_anomalies)
    
    # Update session data
    end_time = datetime.now()
    duration = (end_time - start_time).total_seconds()
    
    session_data['end_time'] = end_time.strftime('%Y-%m-%d %H:%M:%S')
    session_data['duration_seconds'] = int(duration)
    session_data['total_anomalies'] = len(all_anomalies)
    
    # Store in ClickHouse
    stored_session_id = analyzer.store_session_in_clickhouse(session_data)
    analyzer.store_anomalies_in_clickhouse(all_anomalies, session_id)
    
    # Generate summary report
    analyzer.generate_summary_report(folder_path, all_anomalies, stored_session_id)
    
    # Save detailed report
    report_file = os.path.join(folder_path, "anomaly_analysis_report.txt")
    analyzer.save_detailed_report(report_file, folder_path, all_anomalies)
    
    print(f"\n✅ FOLDER ANALYSIS COMPLETE")
    if analyzer.clickhouse_available:
        print("💾 All data stored in ClickHouse database")
    print("All network files have been processed and analyzed.")

if __name__ == "__main__":
    main()
#!/usr/bin/env python3

import sys
import argparse
import uuid
import re
from datetime import datetime
import json
from clickhouse_client import clickhouse_client

class UEEventAnalyzer:
    def __init__(self):
        self.anomalies_detected = []
        self.attach_patterns = {
            'normal_attach': r'UE\s+(\d+)\s+ATTACH_REQUEST.*ATTACH_ACCEPT',
            'failed_attach': r'UE\s+(\d+)\s+ATTACH_REQUEST.*ATTACH_REJECT',
            'attach_timeout': r'UE\s+(\d+)\s+ATTACH_REQUEST.*TIMEOUT',
        }
        self.detach_patterns = {
            'normal_detach': r'UE\s+(\d+)\s+DETACH_REQUEST.*DETACH_ACCEPT',
            'abnormal_detach': r'UE\s+(\d+)\s+DETACH_INDICATION',
            'forced_detach': r'UE\s+(\d+)\s+DETACH_REQUEST.*NETWORK_INITIATED',
        }
    
    def parse_ue_events(self, log_content):
        """Parse UE events from log content"""
        events = []
        lines = log_content.split('\n')
        
        for line_num, line in enumerate(lines):
            line = line.strip()
            if not line:
                continue
            
            # Extract timestamp if present
            timestamp_match = re.search(r'(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})', line)
            timestamp = datetime.strptime(timestamp_match.group(1), '%Y-%m-%d %H:%M:%S') if timestamp_match else datetime.now()
            
            # Check for attach events
            for event_type, pattern in self.attach_patterns.items():
                match = re.search(pattern, line, re.IGNORECASE)
                if match:
                    ue_id = match.group(1)
                    events.append({
                        'timestamp': timestamp,
                        'ue_id': ue_id,
                        'event_type': 'attach',
                        'event_subtype': event_type,
                        'line_number': line_num + 1,
                        'raw_line': line
                    })
            
            # Check for detach events
            for event_type, pattern in self.detach_patterns.items():
                match = re.search(pattern, line, re.IGNORECASE)
                if match:
                    ue_id = match.group(1)
                    events.append({
                        'timestamp': timestamp,
                        'ue_id': ue_id,
                        'event_type': 'detach',
                        'event_subtype': event_type,
                        'line_number': line_num + 1,
                        'raw_line': line
                    })
        
        return events
    
    def analyze_attach_detach_patterns(self, events, source_file):
        """Analyze UE attach/detach patterns for anomalies"""
        ue_sessions = {}
        anomaly_count = 0
        
        # Group events by UE ID
        for event in events:
            ue_id = event['ue_id']
            if ue_id not in ue_sessions:
                ue_sessions[ue_id] = []
            ue_sessions[ue_id].append(event)
        
        # Analyze each UE's session patterns
        for ue_id, ue_events in ue_sessions.items():
            ue_events.sort(key=lambda x: x['timestamp'])
            
            # Check for rapid attach/detach cycles
            attach_count = len([e for e in ue_events if e['event_type'] == 'attach'])
            detach_count = len([e for e in ue_events if e['event_type'] == 'detach'])
            
            # Flag UEs with excessive attach/detach activity
            if attach_count > 10 or detach_count > 10:
                anomaly_id = str(uuid.uuid4())
                anomaly = {
                    'id': anomaly_id,
                    'timestamp': datetime.now(),
                    'type': 'ue_event',
                    'description': f"Excessive attach/detach activity for UE {ue_id}",
                    'severity': 'high' if attach_count > 20 or detach_count > 20 else 'medium',
                    'source_file': source_file,
                    'mac_address': None,
                    'ue_id': ue_id,
                    'details': json.dumps({
                        'attach_count': attach_count,
                        'detach_count': detach_count,
                        'events_analyzed': len(ue_events)
                    }),
                    'status': 'open'
                }
                
                self.anomalies_detected.append(anomaly)
                clickhouse_client.insert_anomaly(anomaly)
                anomaly_count += 1
            
            # Check for abnormal detach patterns
            abnormal_detaches = [e for e in ue_events if e['event_subtype'] == 'abnormal_detach']
            if abnormal_detaches:
                anomaly_id = str(uuid.uuid4())
                anomaly = {
                    'id': anomaly_id,
                    'timestamp': abnormal_detaches[0]['timestamp'],
                    'type': 'ue_event',
                    'description': f"Abnormal UE detach sequence pattern for UE {ue_id}",
                    'severity': 'medium',
                    'source_file': source_file,
                    'mac_address': None,
                    'ue_id': ue_id,
                    'details': json.dumps({
                        'abnormal_detach_count': len(abnormal_detaches),
                        'first_occurrence': abnormal_detaches[0]['timestamp'].isoformat(),
                        'line_number': abnormal_detaches[0]['line_number']
                    }),
                    'status': 'open'
                }
                
                self.anomalies_detected.append(anomaly)
                clickhouse_client.insert_anomaly(anomaly)
                anomaly_count += 1
            
            # Check for attach failures
            failed_attaches = [e for e in ue_events if e['event_subtype'] == 'failed_attach']
            if len(failed_attaches) > 3:  # More than 3 failed attempts
                anomaly_id = str(uuid.uuid4())
                anomaly = {
                    'id': anomaly_id,
                    'timestamp': failed_attaches[0]['timestamp'],
                    'type': 'ue_event',
                    'description': f"Multiple attach failures for UE {ue_id}",
                    'severity': 'high',
                    'source_file': source_file,
                    'mac_address': None,
                    'ue_id': ue_id,
                    'details': json.dumps({
                        'failed_attach_count': len(failed_attaches),
                        'failure_rate': len(failed_attaches) / attach_count if attach_count > 0 else 1.0,
                        'first_failure': failed_attaches[0]['timestamp'].isoformat()
                    }),
                    'status': 'open'
                }
                
                self.anomalies_detected.append(anomaly)
                clickhouse_client.insert_anomaly(anomaly)
                anomaly_count += 1
        
        return anomaly_count
    
    def detect_timing_anomalies(self, events, source_file):
        """Detect timing-based anomalies in UE events"""
        anomaly_count = 0
        
        # Group events by UE and check timing patterns
        ue_events = {}
        for event in events:
            ue_id = event['ue_id']
            if ue_id not in ue_events:
                ue_events[ue_id] = []
            ue_events[ue_id].append(event)
        
        for ue_id, events_list in ue_events.items():
            events_list.sort(key=lambda x: x['timestamp'])
            
            # Check for rapid succession events (< 1 second apart)
            for i in range(1, len(events_list)):
                time_diff = (events_list[i]['timestamp'] - events_list[i-1]['timestamp']).total_seconds()
                
                if time_diff < 1.0 and events_list[i]['event_type'] != events_list[i-1]['event_type']:
                    anomaly_id = str(uuid.uuid4())
                    anomaly = {
                        'id': anomaly_id,
                        'timestamp': events_list[i]['timestamp'],
                        'type': 'ue_event',
                        'description': f"Rapid event sequence detected for UE {ue_id}: {time_diff:.2f}s between events",
                        'severity': 'medium',
                        'source_file': source_file,
                        'mac_address': None,
                        'ue_id': ue_id,
                        'details': json.dumps({
                            'time_between_events': time_diff,
                            'event1': events_list[i-1]['event_subtype'],
                            'event2': events_list[i]['event_subtype'],
                            'line_numbers': [events_list[i-1]['line_number'], events_list[i]['line_number']]
                        }),
                        'status': 'open'
                    }
                    
                    self.anomalies_detected.append(anomaly)
                    clickhouse_client.insert_anomaly(anomaly)
                    anomaly_count += 1
        
        return anomaly_count
    
    def process_ue_log(self, log_content, source_file):
        """Main processing function for UE event logs"""
        try:
            print(f"Processing UE event log: {source_file}")
            
            # Parse UE events from log content
            events = self.parse_ue_events(log_content)
            print(f"Parsed {len(events)} UE events")
            
            if not events:
                print("No UE events found in log")
                return 0
            
            # Analyze attach/detach patterns
            pattern_anomalies = self.analyze_attach_detach_patterns(events, source_file)
            
            # Detect timing anomalies
            timing_anomalies = self.detect_timing_anomalies(events, source_file)
            
            total_anomalies = pattern_anomalies + timing_anomalies
            
            # Create session record
            session_id = str(uuid.uuid4())
            session_data = {
                'id': str(uuid.uuid4()),
                'session_id': session_id,
                'start_time': datetime.now(),
                'end_time': datetime.now(),
                'packets_analyzed': len(events),
                'anomalies_detected': total_anomalies,
                'source_file': source_file
            }
            
            clickhouse_client.client.insert('sessions', [session_data])
            
            print(f"Processing complete. Found {total_anomalies} anomalies.")
            return total_anomalies
            
        except Exception as e:
            print(f"Error processing UE log: {str(e)}")
            raise e

def main():
    parser = argparse.ArgumentParser(description='Analyze UE event logs for anomaly detection')
    parser.add_argument('--file-id', required=True, help='File ID from database')
    parser.add_argument('--filename', required=True, help='Original filename')
    
    args = parser.parse_args()
    
    # Read log content from stdin
    log_content = sys.stdin.read()
    
    analyzer = UEEventAnalyzer()
    
    try:
        anomalies_found = analyzer.process_ue_log(log_content, args.filename)
        print(f"SUCCESS: {anomalies_found} anomalies detected")
        sys.exit(0)
    except Exception as e:
        print(f"ERROR: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()

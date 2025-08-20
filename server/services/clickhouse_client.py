import clickhouse_connect
import os
from datetime import datetime
from typing import List, Dict, Any, Optional
import json
from decimal import Decimal

def convert_decimals(obj):
    """Convert EDecimal and other decimal types to float for JSON serialization"""
    if hasattr(obj, '__dict__'):
        # Handle objects with __dict__
        return {k: convert_decimals(v) for k, v in obj.__dict__.items()}
    elif isinstance(obj, (list, tuple)):
        # Handle lists and tuples
        return [convert_decimals(item) for item in obj]
    elif isinstance(obj, dict):
        # Handle dictionaries
        return {k: convert_decimals(v) for k, v in obj.items()}
    elif hasattr(obj, '_value') and hasattr(obj, '__float__'):
        # Handle EDecimal and similar decimal types
        return float(obj)
    elif isinstance(obj, Decimal):
        # Handle standard decimal types
        return float(obj)
    elif hasattr(obj, 'isoformat'):
        # Handle datetime objects
        return obj.isoformat()
    else:
        return obj

class ClickHouseClient:
    def __init__(self):
        self.host = os.getenv('CLICKHOUSE_HOST', 'localhost')
        self.port = int(os.getenv('CLICKHOUSE_PORT', '9000'))
        self.database = os.getenv('CLICKHOUSE_DATABASE', 'l1_tool_db')
        self.username = os.getenv('CLICKHOUSE_USERNAME', 'default')
        self.password = os.getenv('CLICKHOUSE_PASSWORD', '')
        
        self.client = clickhouse_connect.get_client(
            host=self.host,
            port=self.port,
            database=self.database,
            username=self.username,
            password=self.password
        )
        
        self._create_tables()
    
    def _create_tables(self):
        """Create tables if they don't exist"""
        
        # Anomalies table
        self.client.command("""
            CREATE TABLE IF NOT EXISTS anomalies (
                id String,
                timestamp DateTime,
                type String,
                description String,
                severity String,
                source_file String,
                mac_address Nullable(String),
                ue_id Nullable(String),
                details Nullable(String),
                status String DEFAULT 'open'
            ) ENGINE = MergeTree()
            ORDER BY timestamp
        """)
        
        # Processed files table
        self.client.command("""
            CREATE TABLE IF NOT EXISTS processed_files (
                id String,
                filename String,
                file_type String,
                file_size UInt64,
                upload_date DateTime,
                processing_status String DEFAULT 'pending',
                anomalies_found UInt32 DEFAULT 0,
                processing_time Nullable(UInt32),
                error_message Nullable(String)
            ) ENGINE = MergeTree()
            ORDER BY upload_date
        """)
        
        # Sessions table
        self.client.command("""
            CREATE TABLE IF NOT EXISTS sessions (
                id String,
                session_id String,
                start_time DateTime,
                end_time Nullable(DateTime),
                packets_analyzed UInt32 DEFAULT 0,
                anomalies_detected UInt32 DEFAULT 0,
                source_file String
            ) ENGINE = MergeTree()
            ORDER BY start_time
        """)
        
        # Metrics table
        self.client.command("""
            CREATE TABLE IF NOT EXISTS metrics (
                id String,
                metric_name String,
                metric_value Float64,
                timestamp DateTime,
                category String
            ) ENGINE = MergeTree()
            ORDER BY timestamp
        """)
    
    def insert_anomaly(self, anomaly_data: Dict[str, Any]) -> str:
        """Insert anomaly into ClickHouse"""
        anomaly_id = anomaly_data.get('id', '')
        
        self.client.insert('anomalies', [anomaly_data])
        return anomaly_id
    
    def get_anomalies(self, limit: int = 50, offset: int = 0, 
                     type_filter: Optional[str] = None, 
                     severity_filter: Optional[str] = None) -> List[Dict[str, Any]]:
        """Get anomalies with filtering"""
        query = "SELECT * FROM anomalies WHERE 1=1"
        params = []
        
        if type_filter:
            query += " AND type = %s"
            params.append(type_filter)
        
        if severity_filter:
            query += " AND severity = %s"
            params.append(severity_filter)
        
        query += " ORDER BY timestamp DESC LIMIT %s OFFSET %s"
        params.extend([limit, offset])
        
        result = self.client.query(query, params)
        rows = [dict(zip(result.column_names, row)) for row in result.result_rows]
        return convert_decimals(rows)
    
    def get_dashboard_metrics(self) -> Dict[str, Any]:
        """Get dashboard metrics"""
        total_anomalies = self.client.query("SELECT count() FROM anomalies").result_rows[0][0]
        sessions_analyzed = self.client.query("SELECT count() FROM sessions").result_rows[0][0]
        files_processed = self.client.query("SELECT count() FROM processed_files WHERE processing_status = 'completed'").result_rows[0][0]
        total_files = self.client.query("SELECT count() FROM processed_files").result_rows[0][0]
        
        detection_rate = (files_processed / total_files * 100) if total_files > 0 else 0
        
        metrics = {
            'totalAnomalies': total_anomalies,
            'sessionsAnalyzed': sessions_analyzed,
            'detectionRate': round(detection_rate, 1),
            'filesProcessed': files_processed
        }
        
        return convert_decimals(metrics)
    
    def get_anomaly_trends(self, days: int = 7) -> List[Dict[str, Any]]:
        """Get anomaly trends for the last N days"""
        query = """
            SELECT 
                toDate(timestamp) as date,
                count() as count
            FROM anomalies 
            WHERE timestamp >= now() - INTERVAL %s DAY
            GROUP BY date
            ORDER BY date
        """
        
        result = self.client.query(query, [days])
        trends = [{'date': str(row[0]), 'count': row[1]} for row in result.result_rows]
        return convert_decimals(trends)
    
    def get_anomaly_type_breakdown(self) -> List[Dict[str, Any]]:
        """Get anomaly breakdown by type"""
        query = """
            SELECT 
                type,
                count() as count,
                count() * 100.0 / (SELECT count() FROM anomalies) as percentage
            FROM anomalies
            GROUP BY type
            ORDER BY count DESC
        """
        
        result = self.client.query(query)
        breakdown = [{'type': row[0], 'count': row[1], 'percentage': round(float(row[2]), 1) if row[2] is not None else None} 
                for row in result.result_rows]
        return convert_decimals(breakdown)
    
    def insert_processed_file(self, file_data: Dict[str, Any]) -> str:
        """Insert processed file record"""
        file_id = file_data.get('id', '')
        self.client.insert('processed_files', [file_data])
        return file_id
    
    def update_file_status(self, file_id: str, status: str, 
                          anomalies_found: Optional[int] = None,
                          processing_time: Optional[int] = None,
                          error_message: Optional[str] = None):
        """Update file processing status"""
        updates = ["processing_status = %s"]
        params = [status]
        
        if anomalies_found is not None:
            updates.append("anomalies_found = %s")
            params.append(anomalies_found)
        
        if processing_time is not None:
            updates.append("processing_time = %s")
            params.append(processing_time)
        
        if error_message is not None:
            updates.append("error_message = %s")
            params.append(error_message)
        
        params.append(file_id)
        
        query = f"ALTER TABLE processed_files UPDATE {', '.join(updates)} WHERE id = %s"
        self.client.command(query, params)
    
    def get_processed_files(self) -> List[Dict[str, Any]]:
        """Get all processed files"""
        result = self.client.query("SELECT * FROM processed_files ORDER BY upload_date DESC")
        files = [dict(zip(result.column_names, row)) for row in result.result_rows]
        return convert_decimals(files)

# Global client instance
clickhouse_client = ClickHouseClient()

# Command line interface for storage queries
if __name__ == "__main__":
    import sys
    import json
    
    if len(sys.argv) > 1:
        try:
            request_data = json.loads(sys.argv[1])
            query = request_data.get('query', '')
            params = request_data.get('params', [])
            
            # Execute query and return results
            if query.strip().upper().startswith('SELECT'):
                result = clickhouse_client.client.query(query, params)
                output = [dict(zip(result.column_names, row)) for row in result.result_rows]
                output = convert_decimals(output)
            elif query.strip().upper().startswith('INSERT'):
                clickhouse_client.client.command(query, params)
                output = {"success": True}
            elif query.strip().upper().startswith('ALTER'):
                clickhouse_client.client.command(query, params)
                output = {"success": True}
            else:
                clickhouse_client.client.command(query, params)
                output = {"success": True}
            
            print(json.dumps(output))
            
        except Exception as e:
            print(json.dumps({"error": str(e)}), file=sys.stderr)
            sys.exit(1)

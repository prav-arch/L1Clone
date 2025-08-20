import { createClient, ClickHouseClient } from '@clickhouse/client';

class ClickHouseDB {
  private client: ClickHouseClient;
  private isConnected: boolean = false;

  constructor() {
    // ClickHouse client configuration for pod service
    const config = {
      url: process.env.CLICKHOUSE_URL || 'http://clickhouse-service:8123',
      username: process.env.CLICKHOUSE_USER || 'default',
      password: process.env.CLICKHOUSE_PASSWORD || '',
      database: process.env.CLICKHOUSE_DATABASE || 'l1_anomaly_detection',
    };

    console.log('🔗 Connecting to ClickHouse server at:', config.url);
    this.client = createClient(config);
  }

  async testConnection(): Promise<boolean> {
    try {
      const result = await this.client.query({
        query: 'SELECT 1 as test',
      });
      
      // Verify database and tables exist
      await this.client.query({
        query: 'SELECT count() FROM l1_anomaly_detection.anomalies LIMIT 1'
      });
      
      console.log('✅ ClickHouse connection successful - Real data access enabled');
      this.isConnected = true;
      return true;
    } catch (error: any) {
      console.error('❌ ClickHouse connection failed:', error.message);
      console.error('❌ REAL DATA ONLY: Cannot fallback to sample data');
      console.error('Please ensure ClickHouse pod is running with l1_anomaly_detection database');
      this.isConnected = false;
      throw error;
    }
  }

  async queryWithParams(sql: string, queryParams: Record<string, any>): Promise<any> {
    try {
      const result = await this.client.query({
        query: sql,
        query_params: queryParams,
      });

      const data = await result.json();
      return data.data || [];
    } catch (error) {
      console.error('ClickHouse Query Error:', error);
      throw error;
    }
  }

  async query(sql: string, params: any[] = []): Promise<any> {
    try {
      // Use simple parameter substitution for better ClickHouse compatibility
      let processedQuery = sql;
      if (params && params.length > 0) {
        let paramIndex = 0;
        processedQuery = sql.replace(/\?/g, () => {
          const value = params[paramIndex++];
          if (value === null || value === undefined) return 'NULL';
          return typeof value === 'string' ? `'${value.replace(/'/g, "''")}'` : String(value);
        });
      }

      console.log('Executing ClickHouse Query:', processedQuery);

      // Use minimal settings for better compatibility with older ClickHouse versions
      const result = await this.client.query({
        query: processedQuery,
        clickhouse_settings: {
          // Minimal settings for ClickHouse 18.x compatibility
          use_client_time_zone: 1
        }
      });

      const data = await result.json();
      return data.data || [];
    } catch (error: any) {
      console.error('ClickHouse Query Error:', error);
      throw error;
    }
  }

  async insert(table: string, data: any[]): Promise<void> {
    if (!this.isConnected && !(await this.testConnection())) {
      throw new Error('ClickHouse not available');
    }

    try {
      await this.client.insert({
        table,
        values: data,
        format: 'JSONEachRow',
      });
    } catch (error) {
      console.error('ClickHouse Insert Error:', error);
      throw error;
    }
  }

  async command(sql: string): Promise<void> {
    if (!this.isConnected && !(await this.testConnection())) {
      throw new Error('ClickHouse not available');
    }

    try {
      await this.client.command({ query: sql });
    } catch (error) {
      console.error('ClickHouse Command Error:', error);
      throw error;
    }
  }

  getClient(): ClickHouseClient {
    return this.client;
  }

  isAvailable(): boolean {
    return this.isConnected;
  }
}

export const clickhouse = new ClickHouseDB();
export default clickhouse;
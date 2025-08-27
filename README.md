# L1 Troubleshooting Tool - Clone

## Quick Start

This is a complete L1 Network Troubleshooting System with full TSLAM-4B AI integration and ClickHouse database support.

### Prerequisites

1. **Node.js 18+** and **Python 3.11+**
2. **Tesla P40 GPU** (24GB VRAM) with proper CUDA drivers
3. **ClickHouse Server** running on `127.0.0.1:8123`
4. **TSLAM-4B Model** installed at `/home/users/praveen.joe/TSLAM-4B`

### Installation

```bash
# Install Node.js dependencies
npm install

# Install Python dependencies
pip install -r requirements_mistral.txt

# Set up database schema
npm run db:push
```

### Running the Application

```bash
# Start the development server
npm run dev
```

The application will be available at `http://0.0.0.0:5000`

## Core Features

### 🔍 Advanced Anomaly Detection
- **Fronthaul Analysis**: DU-RU communication monitoring
- **UE Event Processing**: Mobility and attachment pattern detection  
- **MAC Layer Analysis**: Address conflicts and protocol violations
- **Signal Quality**: RSRP/RSRQ/SINR degradation detection

### 🤖 AI-Powered Recommendations
- **TSLAM-4B Integration**: Real streaming AI recommendations
- **Tesla P40 Optimized**: 4-bit quantization for 24GB VRAM
- **WebSocket Streaming**: Token-by-token response delivery
- **Context-Aware**: Telecommunications-specific troubleshooting

### 📊 Real-Time Dashboard
- **Live Metrics**: Anomaly counts and detection rates
- **Trend Analysis**: Time-series anomaly patterns
- **Interactive Charts**: Recharts-powered visualizations
- **Filtering**: By anomaly type and severity

### 🗄️ Dual Database Support
- **PostgreSQL**: Primary application data with Drizzle ORM
- **ClickHouse**: High-volume analytics at `127.0.0.1:8123`
- **Fallback Logic**: Sample data when databases unavailable

## File Processing

### Supported Formats
- **PCAP Files**: Network packet capture analysis
- **Log Files**: UE event and system log processing
- **Batch Processing**: Entire directory analysis

### Processing Pipeline
1. **Upload**: 100MB file size limit with Multer
2. **Analysis**: Python-based ML algorithms
3. **Storage**: Results in PostgreSQL/ClickHouse
4. **Reporting**: Comprehensive anomaly reports

## Architecture

### Frontend
- **React 18** + **TypeScript** + **Vite**
- **Shadcn/UI** components on **Radix UI**
- **TanStack Query** for server state
- **Wouter** for routing

### Backend
- **Express.js** with **TypeScript**
- **WebSocket** for real-time streaming
- **Drizzle ORM** for type-safe database ops
- **Python services** for ML processing

### AI Integration
- **TSLAM-4B Model**: 4B parameter transformer
- **Streaming Interface**: Real-time recommendation generation
- **Tesla P40 Support**: Optimized for 24GB VRAM
- **Quantization**: 4-bit precision for memory efficiency

## Configuration

### Environment Variables
```bash
DATABASE_URL=your_postgresql_connection_string
CLICKHOUSE_URL=http://127.0.0.1:8123
CLICKHOUSE_DATABASE=l1_anomaly_detection
PORT=5000
```

### TSLAM Model Setup
```bash
# Ensure TSLAM-4B is available at:
/home/users/praveen.joe/TSLAM-4B/

# Tesla P40 GPU requirements:
# - 24GB VRAM
# - CUDA drivers installed
# - 4-bit quantization enabled
```

## API Endpoints

### Dashboard
- `GET /api/dashboard/metrics` - Overview metrics
- `GET /api/dashboard/trends` - Anomaly trends
- `GET /api/dashboard/breakdown` - Type breakdown

### Anomalies
- `GET /api/anomalies` - List anomalies
- `GET /api/anomalies/:id` - Get specific anomaly
- `POST /api/anomalies` - Create anomaly
- `PATCH /api/anomalies/:id/status` - Update status

### Files
- `GET /api/files` - List processed files
- `POST /api/files/upload` - Upload PCAP/log file

### Real-time
- `WebSocket /ws` - Streaming AI recommendations

## Development Scripts

```bash
npm run dev      # Start development server
npm run build    # Build for production
npm run start    # Start production server
npm run check    # TypeScript type checking
npm run db:push  # Push database schema
```

## Python Analysis Scripts

```bash
# Comprehensive L1 analysis
python comprehensive_l1_analyzer.py

# Enhanced ML analysis
python enhanced_ml_analyzer.py

# Unified file processor
python unified_l1_analyzer.py

# ClickHouse batch analyzer
python folder_anomaly_analyzer_clickhouse.py
```

## GPU Hardware Requirements

### Tesla P40 Specifications
- **VRAM**: 24GB GDDR5
- **Compute Capability**: 6.1 (Pascal)
- **Memory Bandwidth**: 547 GB/s
- **CUDA Cores**: 3840

### Model Performance
- **TSLAM-4B**: ~22GB VRAM usage with 4-bit quantization
- **Inference Speed**: 15-25 tokens/second
- **Context Length**: Up to 4096 tokens
- **Precision**: Mixed FP16/INT4 for optimal performance

## Troubleshooting

### ClickHouse Connection Issues
```bash
# Check ClickHouse status
curl http://127.0.0.1:8123/ping

# Verify database exists
curl "http://127.0.0.1:8123/?query=SHOW DATABASES"
```

### GPU Memory Issues
```bash
# Monitor GPU usage
nvidia-smi

# Clear GPU memory
python -c "import torch; torch.cuda.empty_cache()"
```

### TSLAM Model Loading
- Ensure model path is correct: `/home/users/praveen.joe/TSLAM-4B`
- Check available VRAM: 22GB+ required
- Verify CUDA installation and drivers

## License

MIT License - This is a development clone for independent feature work.
# L1 Troubleshooting Tool - Clone Information

## Clone Details

**Original Project**: L1 Troubleshooting Tool  
**Clone Created**: August 20, 2025  
**Clone Purpose**: Independent development environment for future enhancements  
**Status**: Complete functional clone with all features

## What's Been Cloned

### ✅ Complete Application Structure
- **Frontend**: React 18 + TypeScript + Vite + Shadcn/UI components
- **Backend**: Node.js + Express + TypeScript + WebSocket support
- **Database**: PostgreSQL schema with Drizzle ORM + ClickHouse integration
- **AI Integration**: Full TSLAM-4B model support with Tesla P40 optimization

### ✅ Core Features Preserved
- **Anomaly Detection**: All 4-algorithm ML ensemble (Isolation Forest, DBSCAN, One-Class SVM, LOF)
- **File Processing**: PCAP and log file analysis with 100MB upload limit
- **Real-time Dashboard**: Live metrics, trends, and interactive charts
- **WebSocket Streaming**: Token-by-token AI recommendation delivery
- **Dual Database**: PostgreSQL primary + ClickHouse analytics fallback

### ✅ Python Processing Services
- `enhanced_ml_analyzer.py` - Advanced ML anomaly detection
- `comprehensive_l1_analyzer.py` - Complete L1 scenario coverage
- `unified_l1_analyzer.py` - Single-file PCAP/text processor
- `folder_anomaly_analyzer_clickhouse.py` - Batch directory analysis
- `server/services/tslam_service.py` - TSLAM-4B AI integration
- `server/services/pcap_processor.py` - Network packet analysis
- `server/services/ue_analyzer.py` - UE event processing

### ✅ Configuration Files
- `package.json` - Node.js dependencies and scripts
- `tsconfig.json` - TypeScript configuration
- `vite.config.ts` - Frontend build configuration
- `tailwind.config.ts` - UI styling configuration
- `drizzle.config.ts` - Database ORM configuration
- `components.json` - Shadcn/UI component configuration
- `pyproject.toml` - Python project configuration
- `requirements_mistral.txt` - Python dependencies

### ✅ Documentation
- `README.md` - Complete setup and usage guide
- `replit.md` - Project architecture and preferences
- `.env.example` - Environment variable template
- `.gitignore` - Version control exclusions

## Key Technical Specifications

### TSLAM AI Integration
- **Model**: TSLAM-4B (4 billion parameters)
- **Hardware**: Tesla P40 GPU (24GB VRAM)
- **Optimization**: 4-bit quantization, 22GB memory allocation
- **Streaming**: Real-time token-by-token responses via WebSocket
- **Location**: `/home/users/praveen.joe/TSLAM-4B`

### Database Configuration
- **Primary**: PostgreSQL with Drizzle ORM
- **Analytics**: ClickHouse at `127.0.0.1:8123`
- **Database**: `l1_anomaly_detection`
- **Fallback**: Sample data when ClickHouse unavailable

### Network Analysis Capabilities
- **Fronthaul Monitoring**: DU-RU communication analysis
- **UE Event Processing**: Mobility and attachment patterns
- **MAC Layer Analysis**: Address conflicts and protocol violations
- **Signal Quality**: RSRP/RSRQ/SINR degradation detection
- **Protocol Validation**: L1 frame structure and timing verification

### File Processing Pipeline
1. **Upload**: Web interface with 100MB limit
2. **Detection**: Auto-detection of PCAP vs log files
3. **Analysis**: Python-based ML algorithms
4. **Storage**: Results in PostgreSQL/ClickHouse
5. **Reporting**: Comprehensive anomaly reports with recommendations

## Usage Instructions

### Quick Start
```bash
npm install
pip install -r requirements_mistral.txt
npm run dev
```

### Development Server
- **URL**: http://0.0.0.0:5000
- **API**: REST endpoints + WebSocket streaming
- **Hot Reload**: Vite HMR for frontend changes
- **Auto-restart**: tsx for backend TypeScript

### Running Analysis Scripts
```bash
# Comprehensive L1 analysis
python comprehensive_l1_analyzer.py

# Enhanced ML analysis with all algorithms
python enhanced_ml_analyzer.py

# Batch folder processing
python folder_anomaly_analyzer_clickhouse.py
```

## Deployment

This application can be deployed independently with its own environment configuration.iguration.

## Next Steps

1. **Environment Setup**: Configure `.env` file with your database credentials
2. **Database Migration**: Run `npm run db:push` to set up schema
3. **ClickHouse Setup**: Ensure ClickHouse is running on local desktop
4. **TSLAM Verification**: Confirm TSLAM-4B model availability
5. **Development**: Begin independent feature development

## Clone Verification

All essential components have been successfully cloned:
- ✅ Frontend application (React + TypeScript)
- ✅ Backend API (Express + WebSocket)
- ✅ Database schema (PostgreSQL + ClickHouse)
- ✅ Python ML services (4-algorithm ensemble)
- ✅ TSLAM AI integration (Tesla P40 optimized)
- ✅ Configuration files (complete setup)
- ✅ Documentation (README + guides)

The cloned application is ready for independent development work.
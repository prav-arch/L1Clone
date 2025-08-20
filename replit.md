# L1 Troubleshooting Tool - Clone

## Overview

This is a complete clone of the L1 Troubleshooting system - a full-stack web application designed for L1 network troubleshooting and anomaly detection, specifically focused on 5G network monitoring. The system analyzes PCAP files and network logs to detect various types of anomalies including fronthaul issues, UE events, MAC address irregularities, and protocol violations. It features real-time analysis, AI-powered recommendations through TSLAM integration, and a comprehensive dashboard for monitoring network health.

**Cloned on (2025-08-20)**: Complete application clone created for independent development work. All features from original system preserved including TSLAM-4B integration with Tesla P40 GPU optimization, comprehensive L1 troubleshooting analyzer covering all scenarios: UE events, fronthaul DU-RU issues, MAC anomalies, protocol violations, signal quality (RSRP/RSRQ/SINR), and performance metrics. ClickHouse database integration at 127.0.0.1:8123 maintained with real streaming AI recommendations.

## User Preferences

Preferred communication style: Simple, everyday language. No emojis should be used anywhere in code, output, or documentation.

## System Architecture

### Frontend Architecture
- **Framework**: React 18 with TypeScript using Vite as the build tool
- **UI Components**: Shadcn/ui component library built on Radix UI primitives
- **Styling**: Tailwind CSS with CSS variables for theming
- **State Management**: TanStack Query (React Query) for server state management
- **Routing**: Wouter for lightweight client-side routing
- **Real-time Communication**: WebSocket client for streaming AI recommendations

### Backend Architecture
- **Runtime**: Node.js with Express.js framework
- **Language**: TypeScript with ES modules
- **Database**: PostgreSQL with Drizzle ORM for type-safe database operations
- **Database Provider**: Neon Database (PostgreSQL-compatible serverless)
- **File Processing**: Python services for PCAP analysis and log processing
- **AI Integration**: TSLAM 4B model integration for generating troubleshooting recommendations
- **Real-time Communication**: WebSocket server for streaming responses

## Key Components

### Database Schema (Drizzle)
- **Anomalies Table**: Stores detected anomalies with type, severity, description, and status
- **Processed Files Table**: Tracks uploaded files and their processing status
- **Sessions Table**: Records analysis sessions with packet counts and metrics
- **Metrics Table**: Stores performance and analysis metrics for dashboard

### API Structure
- **REST Endpoints**: Standard CRUD operations for anomalies, files, and sessions
- **WebSocket Integration**: Real-time streaming for AI-generated recommendations
- **File Upload**: Multer-based file handling with 100MB size limit
- **Error Handling**: Centralized error handling middleware

### Processing Services (Python)
- **PCAP Processor**: Analyzes network packet captures using Scapy with 4-algorithm ML ensemble
- **UE Event Analyzer**: Advanced HDF5-to-text parser for UE Attach/Detach event anomaly detection
- **Unified Analyzer**: Single-file processor for both PCAP and text files with auto-detection
- **Folder Analyzer**: Batch processor for entire directories with comprehensive reporting
- **ML Anomaly Detection**: Isolation Forest, DBSCAN, One-Class SVM, LOF algorithms for real-time monitoring
- **ClickHouse Client**: Alternative data storage for high-volume analytics
- **TSLAM Service**: AI model integration for generating troubleshooting recommendations

### Frontend Pages
- **Dashboard**: Real-time metrics overview with charts and trend analysis
- **Anomalies**: Detailed anomaly listing with filtering and AI recommendations
- **File Manager**: Upload interface and processing status tracking

## Data Flow

1. **File Upload**: Users upload PCAP or log files through the web interface
2. **Processing**: Python services analyze files and detect anomalies
3. **Storage**: Results are stored in PostgreSQL database via Drizzle ORM
4. **Real-time Updates**: WebSocket connections provide live updates during processing
5. **AI Analysis**: TSLAM model generates troubleshooting recommendations on demand
6. **Dashboard Display**: React Query fetches and displays real-time metrics and anomalies

## External Dependencies

### Database
- **Primary**: Neon Database (PostgreSQL) for main application data
- **Alternative**: ClickHouse for high-volume analytics (optional)

### AI Model
- **TSLAM 4B**: Transformer-based language model for network troubleshooting
- **Hugging Face Transformers**: Model loading and inference

### Python Libraries
- **Scapy**: Network packet analysis
- **ClickHouse Connect**: Database connectivity for analytics
- **PyTorch**: AI model inference

### Node.js Dependencies
- **Express**: Web server framework
- **WebSocket**: Real-time communication
- **Multer**: File upload handling
- **Drizzle ORM**: Database operations

## Deployment Strategy

### Development
- **Frontend**: Vite dev server with HMR
- **Backend**: Direct TypeScript execution with tsx
- **Database**: Drizzle kit for schema management and migrations

### Production
- **Build Process**: Vite builds frontend, esbuild bundles backend
- **Static Assets**: Frontend built to dist/public directory
- **Server**: Express serves both API and static files
- **Environment**: Uses DATABASE_URL for PostgreSQL connection

### Key Features
- **Dual-Layer Analysis**: PCAP-based DU-RU communication + UE event mobility detection
- **Advanced ML Algorithms**: 4-algorithm ensemble voting for high-confidence anomaly detection
- **HDF5 Text Processing**: Flexible parser for multiple text formats from HDF5 conversions
- **Batch Processing**: Folder-based analyzer processes all files automatically
- **Unified Interface**: Single command handles both PCAP and text files
- **Comprehensive Reporting**: Line-by-line issue identification with MAC address reporting and summary reports
- **Auto-Detection**: Automatically detects file types and processing requirements
- **Real-time Processing**: Live updates during file analysis
- **AI Integration**: TSLAM 4B model for expert-level troubleshooting recommendations
- **Responsive Design**: Mobile-friendly interface with Tailwind CSS

## Clone-Specific Information

### Tesla P40 GPU Configuration
- **VRAM**: 24GB with 4-bit quantization support
- **Memory Allocation**: 22GB reserved for TSLAM-4B model
- **Compute Capability**: 6.1 (Pascal architecture)
- **Optimizations**: Tesla P40-specific model quantization enabled

### TSLAM Integration
- **Model Path**: `/home/users/praveen.joe/TSLAM-4B`
- **Streaming**: Token-by-token real AI responses
- **Hardware Optimization**: Configured for Tesla P40 24GB VRAM
- **Service Integration**: Direct backend routes to TSLAM service

### ClickHouse Configuration
- **Database**: `l1_anomaly_detection` 
- **Connection**: `127.0.0.1:8123`
- **Compatibility**: Version 18+ support
- **Fallback**: Sample data when ClickHouse unavailable
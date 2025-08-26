
# Remote LLM Server Setup Instructions

## Prerequisites on Remote Server (10.193.0.4)

### 1. System Requirements
- Linux-based system (Ubuntu/CentOS/RHEL)
- Python 3.8+
- At least 8GB RAM for 7B models
- 20GB+ disk space

### 2. Install Dependencies

```bash
# Run the installation script
chmod +x install_llama_cpp.sh
./install_llama_cpp.sh

# Or install manually:
sudo apt-get update
sudo apt-get install -y build-essential cmake git python3 python3-pip
pip3 install requests websockets
```

### 3. Install llama.cpp

```bash
cd /tmp
git clone https://github.com/ggerganov/llama.cpp.git
cd llama.cpp
mkdir build && cd build
cmake .. -DLLAMA_CUDA=OFF  # Use -DLLAMA_CUDA=ON if you have NVIDIA GPU
make -j$(nproc)
```

## Model Setup

### 1. Download GGUF Model
Place your GGUF model file in a directory on the remote server:

```bash
# Example locations:
mkdir -p /opt/llm_models
# Download your model to: /opt/llm_models/your-model.gguf

# Or use existing model path if you already have it
```

### 2. Verify Model
```bash
ls -la /path/to/your/model.gguf
file /path/to/your/model.gguf  # Should show binary data
```

## Running the Remote LLM Server

### 1. Copy Server Script
Upload `remote_llm_server.py` to your remote server:

```bash
# Copy to remote server (from your local machine)
scp remote_llm_server.py user@10.193.0.4:/home/user/
ssh user@10.193.0.4
```

### 2. Start the Server

```bash
# Basic usage
python3 remote_llm_server.py --model-path /path/to/your/model.gguf

# With custom host/port
python3 remote_llm_server.py \
    --model-path /opt/llm_models/mistral-7b-instruct.gguf \
    --host 0.0.0.0 \
    --port 8080

# Run in background
nohup python3 remote_llm_server.py \
    --model-path /opt/llm_models/mistral-7b-instruct.gguf \
    --host 0.0.0.0 \
    --port 8080 > llm_server.log 2>&1 &
```

### 3. Verify Server is Running

```bash
# Check if server is running
curl http://localhost:8080/health

# Check if WebSocket is accessible
netstat -tulpn | grep 8080

# View logs
tail -f llm_server.log
```

## Server Endpoints

Once running, the server provides:

- **Health Check**: `GET http://10.193.0.4:8080/health`
- **REST API**: `POST http://10.193.0.4:8080/api/generate`
- **WebSocket**: `ws://10.193.0.4:8080/ws/analyze`

## Firewall Configuration

Ensure port 8080 is open:

```bash
# Ubuntu/Debian
sudo ufw allow 8080

# CentOS/RHEL
sudo firewall-cmd --permanent --add-port=8080/tcp
sudo firewall-cmd --reload

# Check if port is open
sudo ss -tulpn | grep 8080
```

## Testing from Local Machine

Use your existing test scripts:

```bash
# Test from your local machine
python3 test_remote_llm.py 10.193.0.4 8080
```

## Troubleshooting

### Common Issues:

1. **Port already in use**:
   ```bash
   sudo netstat -tulpn | grep 8080
   # Kill existing process or use different port
   ```

2. **Model not found**:
   ```bash
   ls -la /path/to/model.gguf
   # Verify path is correct
   ```

3. **Permission denied**:
   ```bash
   chmod +x remote_llm_server.py
   # Ensure script is executable
   ```

4. **llama.cpp not found**:
   ```bash
   which llama-server
   # Or check: /tmp/llama.cpp/build/bin/llama-server
   ```

### Checking Logs:
```bash
# Server logs
tail -f llm_server.log

# System logs
journalctl -f | grep python3
```

## Performance Tuning

For better performance:

```bash
# Use more CPU threads
python3 remote_llm_server.py \
    --model-path /path/to/model.gguf \
    --threads 8

# For GPU acceleration (if available)
cmake .. -DLLAMA_CUDA=ON  # During llama.cpp build
```

## Security Notes

- The server binds to `0.0.0.0:8080` by default (accessible from any IP)
- Consider using firewall rules to restrict access
- For production, add authentication and SSL/TLS

## Script Arguments

```bash
python3 remote_llm_server.py --help

Options:
  --model-path PATH    Path to GGUF model file (required)
  --host HOST         Host to bind to (default: 0.0.0.0)  
  --port PORT         Port to bind to (default: 8080)
  --no-llama-server   Skip starting llama.cpp (for testing)
```

The server will:
1. Initialize the LLM from your model folder
2. Accept prompts from your local machine
3. Stream responses back in real-time
4. Handle multiple concurrent connections
5. Provide health check endpoints

Your local test scripts should work immediately once this server is running!

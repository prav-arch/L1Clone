
#!/bin/bash

echo "Installing llama.cpp on Remote Server"
echo "========================================"

# Update system
echo "Updating system packages..."
sudo apt-get update

# Install dependencies
echo "Installing build dependencies..."
sudo apt-get install -y build-essential cmake git python3 python3-pip

# Install Python dependencies
echo "Installing Python dependencies..."
pip3 install requests websockets

# Clone and build llama.cpp
echo "Cloning llama.cpp..."
cd /tmp
git clone https://github.com/ggerganov/llama.cpp.git
cd llama.cpp

echo "Building llama.cpp..."
mkdir build
cd build
cmake .. -DLLAMA_CUDA=OFF
make -j$(nproc)

echo "llama.cpp installed successfully!"
echo "Binary location: /tmp/llama.cpp/build/bin/llama-server"

# Make scripts executable
chmod +x /tmp/llama.cpp/build/bin/*

echo ""
echo "Installation Complete!"
echo "Next steps:"
echo "1. Download your GGUF model to the remote server"
echo "2. Run the remote_llm_server.py script"
echo ""

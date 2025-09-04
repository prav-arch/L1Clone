
#!/usr/bin/env python3

import asyncio
import websockets
import json
import subprocess
import threading
import time
import os
import sys
from datetime import datetime
from pathlib import Path
import argparse
from http.server import HTTPServer, BaseHTTPRequestHandler
import urllib.parse

class LLMServerHandler:
    def __init__(self, model_path, host="0.0.0.0", port=8080):
        self.model_path = model_path
        self.host = host
        self.port = port
        self.llama_process = None
        self.llama_ready = False
        self.websocket_clients = set()
        self.rhoai_mode = os.getenv("RHOAI_MODEL_SERVING", "false").lower() == "true"
        
        # Validate model exists
        if not os.path.exists(model_path):
            raise FileNotFoundError(f"Model not found at: {model_path}")
        
        print(f"Initializing LLM Server")
        print(f"Model Path: {model_path}")
        print(f"Server: {host}:{port}")
    
    def start_llama_server(self):
        """Start llama.cpp server in background"""
        try:
            # Find llama-server executable
            llama_server_paths = [
                "/usr/local/bin/llama-server",
                "/tmp/llama.cpp/build/bin/llama-server",
                "./llama.cpp/build/bin/llama-server",
                "llama-server"
            ]
            
            llama_server_path = None
            for path in llama_server_paths:
                if os.path.exists(path) or subprocess.run(["which", path.split('/')[-1]], 
                                                        capture_output=True).returncode == 0:
                    llama_server_path = path
                    break
            
            if not llama_server_path:
                raise FileNotFoundError("llama-server not found. Please install llama.cpp")
            
            # RHOAI GPU optimization
            gpu_layers = "35" if self.rhoai_mode and os.getenv("CUDA_VISIBLE_DEVICES") else "0"
            
            cmd = [
                llama_server_path,
                "--model", self.model_path,
                "--host", "127.0.0.1",
                "--port", "8081",
                "--ctx-size", "4096",
                "--n-predict", "-1",
                "--threads", "8" if self.rhoai_mode else "4",
                "--batch-size", "1024" if self.rhoai_mode else "512",
                "--n-gpu-layers", gpu_layers
            ]
            
            print(f"Starting llama.cpp server: {' '.join(cmd)}")
            
            self.llama_process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            # Wait for server to be ready
            for i in range(30):
                try:
                    import requests
                    response = requests.get("http://127.0.0.1:8081/health", timeout=2)
                    if response.status_code == 200:
                        self.llama_ready = True
                        print("Llama.cpp server is ready")
                        return True
                except:
                    pass
                time.sleep(2)
                print(f"Waiting for llama.cpp server... ({i+1}/30)")
            
            print("Failed to start llama.cpp server")
            return False
            
        except Exception as e:
            print(f"Error starting llama.cpp server: {e}")
            return False
    
    async def handle_websocket(self, websocket, path):
        """Handle WebSocket connections for streaming"""
        self.websocket_clients.add(websocket)
        print(f"New WebSocket client connected. Total: {len(self.websocket_clients)}")
        
        try:
            async for message in websocket:
                try:
                    request = json.loads(message)
                    prompt = request.get("prompt", "")
                    max_tokens = request.get("max_tokens", 500)
                    temperature = request.get("temperature", 0.3)
                    stream = request.get("stream", True)
                    
                    print(f"Processing prompt: {prompt[:100]}...")
                    
                    if stream:
                        await self.stream_completion(websocket, prompt, max_tokens, temperature)
                    else:
                        await self.single_completion(websocket, prompt, max_tokens, temperature)
                        
                except json.JSONDecodeError:
                    await websocket.send(json.dumps({
                        "type": "error",
                        "content": "Invalid JSON in request"
                    }))
                except Exception as e:
                    await websocket.send(json.dumps({
                        "type": "error", 
                        "content": f"Processing error: {str(e)}"
                    }))
                    
        except websockets.exceptions.ConnectionClosed:
            pass
        finally:
            self.websocket_clients.discard(websocket)
            print(f"WebSocket client disconnected. Total: {len(self.websocket_clients)}")
    
    async def stream_completion(self, websocket, prompt, max_tokens, temperature):
        """Stream completion response token by token"""
        try:
            import requests
            
            # Prepare request for llama.cpp server
            llama_request = {
                "prompt": prompt,
                "n_predict": max_tokens,
                "temperature": temperature,
                "stream": True,
                "stop": ["</s>", "[/INST]", "Human:", "Assistant:"]
            }
            
            # Stream from llama.cpp
            response = requests.post(
                "http://127.0.0.1:8081/completion",
                json=llama_request,
                stream=True,
                timeout=60
            )
            
            if response.status_code != 200:
                await websocket.send(json.dumps({
                    "type": "error",
                    "content": f"LLM server error: {response.status_code}"
                }))
                return
            
            # Process streaming response
            for line in response.iter_lines():
                if line:
                    try:
                        # Remove "data: " prefix if present
                        line_text = line.decode('utf-8')
                        if line_text.startswith("data: "):
                            line_text = line_text[6:]
                        
                        if line_text.strip() == "[DONE]":
                            break
                            
                        chunk_data = json.loads(line_text)
                        content = chunk_data.get("content", "")
                        
                        if content:
                            await websocket.send(json.dumps({
                                "type": "token",
                                "content": content,
                                "timestamp": datetime.now().isoformat()
                            }))
                            
                    except json.JSONDecodeError:
                        continue
                    except Exception as e:
                        print(f"Streaming error: {e}")
                        continue
            
            # Send completion signal
            await websocket.send(json.dumps({
                "type": "complete",
                "timestamp": datetime.now().isoformat()
            }))
            
        except Exception as e:
            await websocket.send(json.dumps({
                "type": "error",
                "content": f"Streaming failed: {str(e)}"
            }))
    
    async def single_completion(self, websocket, prompt, max_tokens, temperature):
        """Generate single completion response"""
        try:
            import requests
            
            llama_request = {
                "prompt": prompt,
                "n_predict": max_tokens,
                "temperature": temperature,
                "stream": False
            }
            
            response = requests.post(
                "http://127.0.0.1:8081/completion",
                json=llama_request,
                timeout=120
            )
            
            if response.status_code == 200:
                result = response.json()
                content = result.get("content", "No response generated")
                
                await websocket.send(json.dumps({
                    "type": "completion",
                    "content": content,
                    "timestamp": datetime.now().isoformat()
                }))
            else:
                await websocket.send(json.dumps({
                    "type": "error",
                    "content": f"LLM error: {response.status_code}"
                }))
                
        except Exception as e:
            await websocket.send(json.dumps({
                "type": "error",
                "content": f"Completion failed: {str(e)}"
            }))

class HTTPHealthHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/health":
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({
                "status": "healthy",
                "timestamp": datetime.now().isoformat(),
                "service": "remote_llm_server"
            }).encode())
        else:
            self.send_response(404)
            self.end_headers()
    
    def do_POST(self):
        if self.path == "/api/generate":
            try:
                content_length = int(self.headers['Content-Length'])
                post_data = self.rfile.read(content_length)
                request_data = json.loads(post_data.decode('utf-8'))
                
                # Simple REST API response (non-streaming)
                response_data = {
                    "response": f"REST API response to: {request_data.get('prompt', 'No prompt')}",
                    "timestamp": datetime.now().isoformat()
                }
                
                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps(response_data).encode())
                
            except Exception as e:
                self.send_response(500)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({"error": str(e)}).encode())
        else:
            self.send_response(404)
            self.end_headers()
    
    def log_message(self, format, *args):
        pass  # Suppress HTTP logs

async def main():
    parser = argparse.ArgumentParser(description='Remote LLM Server')
    parser.add_argument('--model-path', required=True, 
                       help='Path to GGUF model file')
    parser.add_argument('--host', default='0.0.0.0',
                       help='Host to bind to (default: 0.0.0.0)')
    parser.add_argument('--port', type=int, default=8080,
                       help='Port to bind to (default: 8080)')
    parser.add_argument('--no-llama-server', action='store_true',
                       help='Skip starting llama.cpp server (for testing)')
    
    args = parser.parse_args()
    
    print("Remote LLM Server Starting...")
    print("=" * 50)
    
    # Initialize handler
    handler = LLMServerHandler(
        model_path=args.model_path,
        host=args.host,
        port=args.port
    )
    
    # Start llama.cpp server
    if not args.no_llama_server:
        if not handler.start_llama_server():
            print("Failed to start LLM backend")
            sys.exit(1)
    
    # Start HTTP health server
    http_server = HTTPServer((args.host, args.port), HTTPHealthHandler)
    http_thread = threading.Thread(target=http_server.serve_forever, daemon=True)
    http_thread.start()
    print(f"HTTP server started on {args.host}:{args.port}")
    
    # Start WebSocket server  
    websocket_server = await websockets.serve(
        handler.handle_websocket,
        args.host,
        args.port,
        subprotocols=["analyze"]
    )
    print(f"WebSocket server started on ws://{args.host}:{args.port}/ws/analyze")
    
    print("\nRemote LLM Server is ready!")
    print(f"Health check: http://{args.host}:{args.port}/health")
    print(f"WebSocket: ws://{args.host}:{args.port}/ws/analyze")
    print(f"Press Ctrl+C to stop")
    
    try:
        await websocket_server.wait_closed()
    except KeyboardInterrupt:
        print("\nStopping server...")
        if handler.llama_process:
            handler.llama_process.terminate()
        http_server.shutdown()
        print("Server stopped")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
    except Exception as e:
        print(f"Server error: {e}")
        sys.exit(1)

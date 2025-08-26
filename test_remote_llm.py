
#!/usr/bin/env python3

import asyncio
import websockets
import json
import requests
import time
import sys
from datetime import datetime

class RemoteLLMTester:
    def __init__(self, remote_host="10.193.0.4", remote_port=8080):
        self.remote_host = remote_host
        self.remote_port = remote_port
        self.base_url = f"http://{remote_host}:{remote_port}"
        self.ws_url = f"ws://{remote_host}:{remote_port}/ws/analyze"
        
    def test_health_check(self):
        """Test if remote LLM server is available"""
        print(f"🔍 Testing connection to {self.base_url}")
        try:
            response = requests.get(f"{self.base_url}/health", timeout=10)
            if response.status_code == 200:
                print("✅ Remote LLM server is healthy")
                return True
            else:
                print(f"❌ Server responded with status: {response.status_code}")
                return False
        except requests.exceptions.ConnectionError:
            print(f"❌ Connection failed - server may be down")
            return False
        except requests.exceptions.Timeout:
            print(f"❌ Connection timeout - server may be slow")
            return False
        except Exception as e:
            print(f"❌ Health check failed: {str(e)}")
            return False
    
    async def test_streaming_analysis(self, prompt, test_name="Test"):
        """Test streaming analysis from remote LLM"""
        print(f"\n🚀 Starting {test_name}")
        print(f"📡 Connecting to: {self.ws_url}")
        print(f"📝 Prompt: {prompt[:100]}...")
        
        try:
            async with websockets.connect(self.ws_url, ping_timeout=60) as websocket:
                # Send prompt to remote LLM
                request_data = {
                    "prompt": prompt,
                    "max_tokens": 500,
                    "temperature": 0.3,
                    "stream": True
                }
                
                print("📤 Sending request...")
                await websocket.send(json.dumps(request_data))
                
                # Receive streaming response
                print("📥 Receiving streaming response:")
                print("-" * 60)
                
                response_chunks = []
                start_time = time.time()
                
                async for message in websocket:
                    try:
                        data = json.loads(message)
                        
                        if data.get("type") == "token":
                            # Stream individual tokens
                            token = data.get("content", "")
                            print(token, end="", flush=True)
                            response_chunks.append(token)
                            
                        elif data.get("type") == "chunk":
                            # Stream text chunks
                            chunk = data.get("content", "")
                            print(chunk, end="", flush=True)
                            response_chunks.append(chunk)
                            
                        elif data.get("type") == "complete":
                            # Analysis complete
                            elapsed = time.time() - start_time
                            print(f"\n\n✅ Streaming complete in {elapsed:.2f}s")
                            print(f"📊 Total response length: {len(''.join(response_chunks))} characters")
                            break
                            
                        elif data.get("type") == "error":
                            # Error occurred
                            error_msg = data.get("content", "Unknown error")
                            print(f"\n❌ Error: {error_msg}")
                            break
                            
                    except json.JSONDecodeError:
                        # Handle raw text response
                        print(message, end="", flush=True)
                        response_chunks.append(message)
                
                return "".join(response_chunks)
                
        except websockets.exceptions.ConnectionClosed:
            print(f"\n❌ WebSocket connection closed unexpectedly")
            return None
        except Exception as e:
            print(f"\n❌ Streaming test failed: {str(e)}")
            return None
    
    async def test_telecom_anomaly_analysis(self):
        """Test with telecom-specific anomaly analysis prompt"""
        prompt = """Analyze the following 5G fronthaul anomaly:

ANOMALY DATA:
- Type: Fronthaul Timing Violation
- Severity: Critical
- DU-RU Latency: 150μs (exceeds 100μs threshold)
- Packet Loss: 0.02%
- Jitter: 45μs
- eCPRI Flows: 1,247 packets
- MAC Addresses: DU (00:11:22:33:44:67) ↔ RU (6c:ad:ad:00:03:2a)

REQUIREMENTS:
1. Identify root cause of timing violation
2. Recommend immediate corrective actions
3. Suggest monitoring improvements
4. Assess impact on UE services

Provide streaming analysis with actionable insights for 5G network engineers."""

        return await self.test_streaming_analysis(prompt, "Telecom Anomaly Analysis")
    
    async def test_general_llm_prompt(self):
        """Test with general LLM prompt"""
        prompt = """Explain the key differences between 5G fronthaul and backhaul networks, focusing on:

1. Latency requirements
2. Protocol differences (eCPRI vs others)
3. Network topology
4. Performance monitoring challenges

Provide a comprehensive technical explanation suitable for network engineers."""

        return await self.test_streaming_analysis(prompt, "General LLM Test")
    
    def test_rest_api(self):
        """Test REST API endpoint if available"""
        print(f"\n🔗 Testing REST API endpoint")
        try:
            payload = {
                "prompt": "What are the key 5G fronthaul timing requirements?",
                "max_tokens": 200,
                "temperature": 0.5
            }
            
            response = requests.post(
                f"{self.base_url}/api/generate",
                json=payload,
                timeout=30
            )
            
            if response.status_code == 200:
                result = response.json()
                print("✅ REST API test successful")
                print(f"📝 Response: {result.get('response', 'No response field')[:200]}...")
                return True
            else:
                print(f"❌ REST API failed with status: {response.status_code}")
                return False
                
        except Exception as e:
            print(f"❌ REST API test failed: {str(e)}")
            return False

async def main():
    """Main test function"""
    print("🤖 Remote LLM Streaming Test Script")
    print("=" * 50)
    
    # Configuration
    remote_host = "10.193.0.4"  # Your remote LLM server
    remote_port = 8080
    
    # Override with command line arguments if provided
    if len(sys.argv) >= 2:
        remote_host = sys.argv[1]
    if len(sys.argv) >= 3:
        remote_port = int(sys.argv[2])
    
    tester = RemoteLLMTester(remote_host, remote_port)
    
    # Test 1: Health check
    if not tester.test_health_check():
        print("\n⚠️  Cannot proceed - remote server is not accessible")
        return
    
    # Test 2: REST API (if available)
    tester.test_rest_api()
    
    # Test 3: WebSocket streaming with telecom prompt
    result1 = await tester.test_telecom_anomaly_analysis()
    
    # Test 4: WebSocket streaming with general prompt
    result2 = await tester.test_general_llm_prompt()
    
    # Summary
    print("\n" + "=" * 50)
    print("📋 Test Summary:")
    print(f"✅ Health Check: Passed")
    print(f"{'✅' if result1 else '❌'} Telecom Analysis: {'Passed' if result1 else 'Failed'}")
    print(f"{'✅' if result2 else '❌'} General LLM Test: {'Passed' if result2 else 'Failed'}")
    
    print(f"\n🔧 Connection Details:")
    print(f"   Host: {remote_host}")
    print(f"   Port: {remote_port}")
    print(f"   WebSocket: ws://{remote_host}:{remote_port}/ws/analyze")
    print(f"   REST API: http://{remote_host}:{remote_port}/api/generate")

if __name__ == "__main__":
    print("Usage: python test_remote_llm.py [host] [port]")
    print("Example: python test_remote_llm.py 10.193.0.4 8080")
    print()
    
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n⏹️  Test interrupted by user")
    except Exception as e:
        print(f"\n💥 Test script failed: {str(e)}")

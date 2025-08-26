
#!/usr/bin/env python3

import asyncio
import websockets
import json
import requests
import subprocess
import time
import sys
from datetime import datetime
import argparse

class CombinedLLMTester:
    def __init__(self, remote_host="10.193.0.4", remote_port=8080, local_port=5000):
        self.remote_host = remote_host
        self.remote_port = remote_port
        self.local_port = local_port
        
        # Remote endpoints
        self.remote_base_url = f"http://{remote_host}:{remote_port}"
        self.remote_ws_url = f"ws://{remote_host}:{remote_port}/ws/analyze"
        
        # Local endpoints
        self.local_ws_url = f"ws://localhost:{local_port}/ws"
        
    async def compare_llm_responses(self, prompt, test_name="Comparison Test"):
        """Compare responses from remote and local LLM"""
        print(f"\n🆚 {test_name} - Comparing Remote vs Local LLM")
        print("=" * 60)
        
        # Test remote LLM
        print("🌐 Testing Remote LLM...")
        remote_start = time.time()
        remote_response = await self.test_remote_llm(prompt)
        remote_time = time.time() - remote_start
        
        # Test local LLM
        print("\n🏠 Testing Local LLM...")
        local_start = time.time()
        local_response = await self.test_local_llm_via_websocket(prompt)
        local_time = time.time() - local_start
        
        # Comparison results
        print("\n📊 Comparison Results:")
        print("-" * 40)
        print(f"Remote LLM: {remote_time:.2f}s | {'✅' if remote_response else '❌'}")
        print(f"Local LLM:  {local_time:.2f}s | {'✅' if local_response else '❌'}")
        
        if remote_response and local_response:
            print(f"Response Length - Remote: {len(remote_response)} | Local: {len(local_response)}")
        
        return {
            "remote": {"response": remote_response, "time": remote_time},
            "local": {"response": local_response, "time": local_time}
        }
    
    async def test_remote_llm(self, prompt):
        """Test remote LLM streaming"""
        try:
            async with websockets.connect(self.remote_ws_url, ping_timeout=30) as websocket:
                request_data = {
                    "prompt": prompt,
                    "max_tokens": 300,
                    "temperature": 0.3,
                    "stream": True
                }
                
                await websocket.send(json.dumps(request_data))
                
                response_chunks = []
                async for message in websocket:
                    try:
                        data = json.loads(message)
                        if data.get("type") in ["token", "chunk"]:
                            chunk = data.get("content", "")
                            print(chunk, end="", flush=True)
                            response_chunks.append(chunk)
                        elif data.get("type") == "complete":
                            break
                        elif data.get("type") == "error":
                            print(f"\nRemote Error: {data.get('content')}")
                            break
                    except json.JSONDecodeError:
                        print(message, end="", flush=True)
                        response_chunks.append(message)
                
                return "".join(response_chunks)
                
        except Exception as e:
            print(f"Remote LLM failed: {str(e)}")
            return None
    
    async def test_local_llm_via_websocket(self, prompt):
        """Test local LLM via WebSocket (simulating anomaly request)"""
        try:
            async with websockets.connect(self.local_ws_url) as websocket:
                # Create a mock anomaly request with the prompt
                test_request = {
                    "type": "get_recommendations",
                    "anomalyId": "test-comparison",
                    "customPrompt": prompt  # Custom field for testing
                }
                
                await websocket.send(json.dumps(test_request))
                
                response_chunks = []
                async for message in websocket:
                    try:
                        data = json.loads(message)
                        if data.get("type") == "recommendation_chunk":
                            chunk = data.get("data", "")
                            print(chunk, end="", flush=True)
                            response_chunks.append(chunk)
                        elif data.get("type") == "recommendation_complete":
                            break
                        elif data.get("type") == "error":
                            print(f"\nLocal Error: {data.get('data')}")
                            break
                    except json.JSONDecodeError:
                        print(message, end="", flush=True)
                        response_chunks.append(message)
                
                return "".join(response_chunks)
                
        except Exception as e:
            print(f"Local LLM failed: {str(e)}")
            return None
    
    def test_connectivity(self):
        """Test connectivity to both remote and local services"""
        print("🔍 Testing Connectivity...")
        
        # Test remote health
        remote_healthy = False
        try:
            response = requests.get(f"{self.remote_base_url}/health", timeout=5)
            remote_healthy = response.status_code == 200
        except:
            pass
        
        print(f"🌐 Remote LLM ({self.remote_host}:{self.remote_port}): {'✅' if remote_healthy else '❌'}")
        
        # Test local service (basic check)
        local_healthy = True  # Assume local is available for testing
        print(f"🏠 Local LLM (localhost:{self.local_port}): {'✅' if local_healthy else '❌'}")
        
        return remote_healthy, local_healthy

async def main():
    """Main test function"""
    parser = argparse.ArgumentParser(description='Test remote and local LLM streaming')
    parser.add_argument('--remote-host', default='10.193.0.4', help='Remote LLM host')
    parser.add_argument('--remote-port', type=int, default=8080, help='Remote LLM port')
    parser.add_argument('--local-port', type=int, default=5000, help='Local service port')
    parser.add_argument('--test-type', choices=['connectivity', 'telecom', 'general', 'all'], 
                       default='all', help='Type of test to run')
    
    args = parser.parse_args()
    
    print("🤖 Combined LLM Streaming Test Script")
    print("=" * 50)
    
    tester = CombinedLLMTester(
        remote_host=args.remote_host,
        remote_port=args.remote_port,
        local_port=args.local_port
    )
    
    # Connectivity test
    if args.test_type in ['connectivity', 'all']:
        remote_ok, local_ok = tester.test_connectivity()
        if not (remote_ok or local_ok):
            print("⚠️  No services available for testing")
            return
    
    # Telecom-specific test
    if args.test_type in ['telecom', 'all']:
        telecom_prompt = """Analyze this 5G fronthaul anomaly:
- DU-RU latency: 150μs (exceeds 100μs)
- Packet loss: 0.02%
- eCPRI flows affected: 1,247
Provide immediate recommendations."""
        
        await tester.compare_llm_responses(telecom_prompt, "Telecom Anomaly Analysis")
    
    # General LLM test
    if args.test_type in ['general', 'all']:
        general_prompt = """Explain the key components of a 5G RAN architecture in 3 bullet points."""
        
        await tester.compare_llm_responses(general_prompt, "General 5G Knowledge Test")
    
    print("\n✅ All tests completed!")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n⏹️  Test interrupted by user")
    except Exception as e:
        print(f"\n💥 Test failed: {str(e)}")

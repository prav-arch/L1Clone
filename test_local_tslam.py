#!/usr/bin/env python3

import asyncio
import websockets
import json
import subprocess
import time
import sys
from datetime import datetime

class LocalTSLAMTester:
    def __init__(self, local_port=5000):
        self.local_port = local_port
        self.ws_url = f"ws://localhost:{local_port}/ws"
        
    async def test_local_tslam_websocket(self):
        """Test local TSLAM service via WebSocket"""
        print(f"Testing local TSLAM WebSocket at {self.ws_url}")
        
        try:
            async with websockets.connect(self.ws_url) as websocket:
                # Test recommendation request
                test_request = {
                    "type": "get_recommendations",
                    "anomalyId": "test-anomaly-123"
                }
                
                print("Sending test recommendation request...")
                await websocket.send(json.dumps(test_request))
                
                print("Receiving streaming response:")
                print("-" * 60)
                
                response_chunks = []
                start_time = time.time()
                
                async for message in websocket:
                    try:
                        data = json.loads(message)
                        
                        if data.get("type") == "recommendation_chunk":
                            chunk = data.get("data", "")
                            print(chunk, end="", flush=True)
                            response_chunks.append(chunk)
                            
                        elif data.get("type") == "recommendation_complete":
                            elapsed = time.time() - start_time
                            print(f"\n\nLocal TSLAM streaming complete in {elapsed:.2f}s")
                            break
                            
                        elif data.get("type") == "error":
                            error_msg = data.get("data", "Unknown error")
                            print(f"\nError: {error_msg}")
                            break
                            
                    except json.JSONDecodeError:
                        print(message, end="", flush=True)
                        response_chunks.append(message)
                
                return "".join(response_chunks)
                
        except Exception as e:
            print(f"Local TSLAM test failed: {str(e)}")
            return None
    
    def test_tslam_service_direct(self):
        """Test TSLAM service directly via Python subprocess"""
        print("Testing TSLAM service directly...")
        
        try:
            # Test the TSLAM service directly
            cmd = [
                "python3", 
                "server/services/tslam_service.py",
                "test-anomaly-456",
                "Fronthaul timing violation detected - DU-RU latency exceeded 100μs threshold"
            ]
            
            print(f"Running: {' '.join(cmd)}")
            
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1
            )
            
            print("Direct TSLAM output:")
            print("-" * 60)
            
            # Read streaming output
            for line in process.stdout:
                print(line, end="")
            
            process.wait()
            
            if process.returncode == 0:
                print("Direct TSLAM service test completed successfully")
                return True
            else:
                print(f"TSLAM service failed with exit code: {process.returncode}")
                stderr_output = process.stderr.read()
                if stderr_output:
                    print(f"Error output: {stderr_output}")
                return False
                
        except Exception as e:
            print(f"Direct TSLAM test failed: {str(e)}")
            return False

async def main():
    """Main test function for local TSLAM"""
    print("Local TSLAM Streaming Test Script")
    print("=" * 50)
    
    local_port = 5000
    if len(sys.argv) >= 2:
        local_port = int(sys.argv[1])
    
    tester = LocalTSLAMTester(local_port)
    
    # Test 1: Direct TSLAM service
    print("Test 1: Direct TSLAM Service")
    direct_result = tester.test_tslam_service_direct()
    
    # Test 2: WebSocket via running server (if available)
    print("\nTest 2: Local WebSocket TSLAM")
    ws_result = await tester.test_local_tslam_websocket()
    
    # Summary
    print("\n" + "=" * 50)
    print("Local TSLAM Test Summary:")
    print(f"{'✅' if direct_result else '❌'} Direct Service: {'Passed' if direct_result else 'Failed'}")
    print(f"{'✅' if ws_result else '❌'} WebSocket Test: {'Passed' if ws_result else 'Failed'}")

if __name__ == "__main__":
    print("Usage: python test_local_tslam.py [port]")
    print("Example: python test_local_tslam.py 5000")
    print()
    
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nTest interrupted by user")
    except Exception as e:
        print(f"\nTest script failed: {str(e)}")
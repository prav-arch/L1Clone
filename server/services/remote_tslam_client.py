
#!/usr/bin/env python3

import os
import json
import requests
import websockets
import asyncio
from datetime import datetime

class RemoteTSLAMClient:
    def __init__(self, remote_host="10.193.0.4", remote_port=8080):
        self.remote_host = remote_host
        self.remote_port = remote_port
        self.base_url = f"http://{remote_host}:{remote_port}"
        
    async def stream_analysis(self, prompt, websocket):
        """Stream analysis from remote TSLAM server"""
        try:
            # Connect to remote TSLAM WebSocket
            remote_ws_url = f"ws://{self.remote_host}:{self.remote_port}/ws/analyze"
            
            async with websockets.connect(remote_ws_url) as remote_ws:
                # Send prompt to remote TSLAM
                await remote_ws.send(json.dumps({
                    "prompt": prompt,
                    "max_tokens": 500,
                    "temperature": 0.3
                }))
                
                # Stream response back to client
                async for message in remote_ws:
                    data = json.loads(message)
                    await websocket.send(json.dumps(data))
                    
        except Exception as e:
            error_response = {
                "type": "error",
                "content": f"Remote TSLAM connection failed: {str(e)}",
                "timestamp": datetime.now().isoformat()
            }
            await websocket.send(json.dumps(error_response))
    
    def health_check(self):
        """Check if remote TSLAM server is available"""
        try:
            response = requests.get(f"{self.base_url}/health", timeout=5)
            return response.status_code == 200
        except:
            return False

if __name__ == "__main__":
    client = RemoteTSLAMClient()
    print(f"Remote TSLAM Health: {'✓' if client.health_check() else '✗'}")

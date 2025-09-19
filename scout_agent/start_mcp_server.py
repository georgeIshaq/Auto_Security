#!/usr/bin/env python3
"""
BrightData MCP Server Manager
Starts and manages the BrightData MCP server as a background service
"""

import subprocess
import time
import os
import signal
import sys
import requests
import json
from pathlib import Path

# Configuration
API_TOKEN = "d1792036336c11288061f1ba7972ccb4cceb8b613b12e37c2f12488769ae0886"
MCP_HOST = "localhost"
MCP_PORT = 3000
PROCESS_FILE = Path(__file__).parent / "mcp_server.pid"

class MCPServerManager:
    def __init__(self):
        self.process = None
        
    def start_server(self):
        """Start the BrightData MCP server as a background process"""
        print("Starting BrightData MCP server...")
        
        # Environment variables for the MCP server
        env = os.environ.copy()
        env["API_TOKEN"] = API_TOKEN
        env["PORT"] = str(MCP_PORT)
        
        try:
            # Start the MCP server process
            self.process = subprocess.Popen(
                ["npx", "-y", "@brightdata/mcp"],
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                preexec_fn=os.setsid  # Create new process group
            )
            
            # Save PID for later cleanup
            with open(PROCESS_FILE, "w") as f:
                f.write(str(self.process.pid))
            
            print(f"MCP server started with PID: {self.process.pid}")
            print(f"Server should be accessible at http://{MCP_HOST}:{MCP_PORT}")
            
            # Wait a moment for server to start
            time.sleep(3)
            
            # Test if server is responding
            if self.test_connection():
                print("✅ MCP server is running and accessible!")
                return True
            else:
                print("❌ MCP server started but not responding to health check")
                return False
                
        except Exception as e:
            print(f"Failed to start MCP server: {e}")
            return False
    
    def test_connection(self):
        """Test if the MCP server is responding"""
        try:
            # Try to connect to the MCP server
            response = requests.get(f"http://{MCP_HOST}:{MCP_PORT}/health", timeout=5)
            return response.status_code == 200
        except:
            # If health endpoint doesn't exist, try a basic connection
            try:
                response = requests.get(f"http://{MCP_HOST}:{MCP_PORT}", timeout=5)
                return True  # Any response means server is running
            except:
                return False
    
    def stop_server(self):
        """Stop the MCP server"""
        try:
            if PROCESS_FILE.exists():
                with open(PROCESS_FILE, "r") as f:
                    pid = int(f.read().strip())
                
                print(f"Stopping MCP server (PID: {pid})...")
                
                # Kill the process group to ensure all child processes are terminated
                os.killpg(os.getpgid(pid), signal.SIGTERM)
                
                # Wait for process to terminate
                time.sleep(2)
                
                # Remove PID file
                PROCESS_FILE.unlink()
                print("✅ MCP server stopped")
                
        except Exception as e:
            print(f"Error stopping MCP server: {e}")
    
    def is_running(self):
        """Check if MCP server is currently running"""
        if not PROCESS_FILE.exists():
            return False
            
        try:
            with open(PROCESS_FILE, "r") as f:
                pid = int(f.read().strip())
            
            # Check if process is still running
            os.kill(pid, 0)  # Doesn't actually kill, just checks if process exists
            return self.test_connection()
            
        except (OSError, ProcessLookupError):
            # Process doesn't exist, clean up PID file
            if PROCESS_FILE.exists():
                PROCESS_FILE.unlink()
            return False
    
    def restart_server(self):
        """Restart the MCP server"""
        self.stop_server()
        time.sleep(1)
        return self.start_server()

def main():
    manager = MCPServerManager()
    
    if len(sys.argv) > 1:
        command = sys.argv[1]
        
        if command == "start":
            if manager.is_running():
                print("MCP server is already running")
            else:
                manager.start_server()
                
        elif command == "stop":
            manager.stop_server()
            
        elif command == "restart":
            manager.restart_server()
            
        elif command == "status":
            if manager.is_running():
                print("✅ MCP server is running")
            else:
                print("❌ MCP server is not running")
                
        else:
            print("Usage: python start_mcp_server.py [start|stop|restart|status]")
    else:
        # Default: start if not running
        if not manager.is_running():
            manager.start_server()
        else:
            print("MCP server is already running")

if __name__ == "__main__":
    main()

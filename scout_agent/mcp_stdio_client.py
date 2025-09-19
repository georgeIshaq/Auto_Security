"""
BrightData MCP Client using stdio communication
This client communicates with the MCP server via stdin/stdout
"""

import json
import subprocess
import time
import threading
import queue
import os
import logging
from typing import Dict, Any, Optional
from dataclasses import dataclass

logger = logging.getLogger(__name__)

@dataclass
class MCPResponse:
    """Structure for MCP response data"""
    success: bool
    data: Any
    error: Optional[str] = None
    metadata: Optional[Dict] = None

class BrightDataMCPStdioClient:
    """
    Client for communicating with BrightData MCP server via stdio
    """
    
    def __init__(self):
        self.process = None
        self.request_id = 0
        self.pending_requests = {}
        self.response_queue = queue.Queue()
        self.reader_thread = None
        self.api_token = "d1792036336c11288061f1ba7972ccb4cceb8b613b12e37c2f12488769ae0886"
        
    def start(self):
        """Start the MCP server process"""
        try:
            env = os.environ.copy()
            env["API_TOKEN"] = self.api_token
            
            # Start the MCP server as subprocess
            self.process = subprocess.Popen(
                ["npx", "-y", "@brightdata/mcp"],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=env,
                text=True,
                bufsize=0
            )
            
            # Start reader thread to handle responses
            self.reader_thread = threading.Thread(target=self._read_responses, daemon=True)
            self.reader_thread.start()
            
            # Initialize MCP connection
            self._send_initialize()
            
            # Clear any initialization responses from the queue
            time.sleep(3)  # Give time for initialization
            while not self.response_queue.empty():
                try:
                    init_response = self.response_queue.get_nowait()
                    logger.debug(f"Clearing initialization response: {init_response}")
                except queue.Empty:
                    break
            
            logger.info("MCP client started successfully")
            return True
            
        except Exception as e:
            logger.error(f"Failed to start MCP client: {e}")
            return False
    
    def stop(self):
        """Stop the MCP server process"""
        if self.process:
            self.process.terminate()
            self.process.wait(timeout=5)
            self.process = None
            
    def _get_next_id(self):
        """Get next request ID"""
        self.request_id += 1
        return str(self.request_id)
    
    def _send_request(self, method: str, params: Dict[str, Any] = None) -> MCPResponse:
        """Send a request to the MCP server"""
        if not self.process:
            return MCPResponse(success=False, data=None, error="MCP server not started")
        
        request_id = self._get_next_id()
        request = {
            "jsonrpc": "2.0",
            "id": request_id,
            "method": method,
            "params": params or {}
        }
        
        try:
            # Send request
            request_json = json.dumps(request) + "\n"
            self.process.stdin.write(request_json)
            self.process.stdin.flush()
            
            # Wait for response (with timeout)
            start_time = time.time()
            timeout = 30
            
            while time.time() - start_time < timeout:
                try:
                    response = self.response_queue.get(timeout=1)
                    logger.debug(f"Received response for request {request_id}: {response}")
                    
                    if response.get("id") == request_id:
                        if "error" in response:
                            return MCPResponse(
                                success=False,
                                data=None,
                                error=response["error"].get("message", "Unknown error")
                            )
                        return MCPResponse(
                            success=True,
                            data=response.get("result"),
                            metadata={"request_id": request_id}
                        )
                    else:
                        # Put it back if it's not our response
                        self.response_queue.put(response)
                        logger.debug(f"Response ID mismatch: expected {request_id}, got {response.get('id')}")
                except queue.Empty:
                    continue
            
            return MCPResponse(success=False, data=None, error="Request timeout")
            
        except Exception as e:
            logger.error(f"Failed to send MCP request: {e}")
            return MCPResponse(success=False, data=None, error=str(e))
    
    def _read_responses(self):
        """Read responses from MCP server in background thread"""
        if not self.process:
            return
            
        try:
            for line in iter(self.process.stdout.readline, ''):
                if line.strip():
                    try:
                        response = json.loads(line.strip())
                        self.response_queue.put(response)
                    except json.JSONDecodeError as e:
                        logger.warning(f"Failed to parse MCP response: {e}")
                        
        except Exception as e:
            logger.error(f"Error reading MCP responses: {e}")
    
    def _send_initialize(self):
        """Send initialize request to MCP server"""
        init_request = {
            "jsonrpc": "2.0",
            "id": "1",
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {
                    "tools": {}
                },
                "clientInfo": {
                    "name": "AutoSecurity Scout Agent",
                    "version": "1.0.0"
                }
            }
        }
        
        try:
            request_json = json.dumps(init_request) + "\n"
            self.process.stdin.write(request_json)
            self.process.stdin.flush()
            
            # Wait for initialization response
            time.sleep(2)
            
            # Send initialized notification
            initialized = {
                "jsonrpc": "2.0",
                "method": "notifications/initialized"
            }
            notification_json = json.dumps(initialized) + "\n"
            self.process.stdin.write(notification_json)
            self.process.stdin.flush()
            
            # Wait a bit more for the server to be ready
            time.sleep(1)
            
        except Exception as e:
            logger.error(f"Failed to initialize MCP: {e}")
    
    def list_tools(self) -> MCPResponse:
        """List available tools from the MCP server"""
        return self._send_request("tools/list")
    
    def call_tool(self, tool_name: str, arguments: Dict[str, Any]) -> MCPResponse:
        """Call a specific tool on the MCP server"""
        params = {
            "name": tool_name,
            "arguments": arguments
        }
        return self._send_request("tools/call", params)
    
    def scrape_as_markdown(self, url: str) -> MCPResponse:
        """Scrape a web page and return as markdown"""
        return self.call_tool("scrape_as_markdown", {"url": url})
    
    def search_engine(self, query: str, engine: str = "google", max_results: int = 10) -> MCPResponse:
        """Search using search engine (google, bing, or yandex)"""
        return self.call_tool("search_engine", {
            "query": query,
            "engine": engine,
            "max_results": max_results
        })

# Convenience function
def create_mcp_client() -> BrightDataMCPStdioClient:
    """Create and start an MCP client"""
    client = BrightDataMCPStdioClient()
    if client.start():
        return client
    else:
        raise Exception("Failed to start MCP client")

# Example usage
if __name__ == "__main__":
    print("Testing BrightData MCP stdio client...")
    
    try:
        client = create_mcp_client()
        time.sleep(2)  # Give server time to start
        
        # List available tools
        print("\nListing available tools...")
        tools_response = client.list_tools()
        if tools_response.success:
            print("✅ Tools listed successfully:")
            print(json.dumps(tools_response.data, indent=2))
        else:
            print(f"❌ Failed to list tools: {tools_response.error}")
        
        # Test web scraping
        print("\nTesting web scraping...")
        scrape_response = client.scrape_as_markdown("https://httpbin.org/html")
        if scrape_response.success:
            print("✅ Scraping successful!")
            print(f"Response preview: {str(scrape_response.data)[:200]}...")
        else:
            print(f"❌ Scraping failed: {scrape_response.error}")
        
        # Test search engine
        print("\nTesting search engine...")
        search_response = client.search_engine("CVE security vulnerability", max_results=3)
        if search_response.success:
            print("✅ Search successful!")
            print(f"Search results preview: {str(search_response.data)[:200]}...")
        else:
            print(f"❌ Search failed: {search_response.error}")
            
        client.stop()
        
    except Exception as e:
        print(f"❌ Test failed: {e}")

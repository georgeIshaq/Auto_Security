#!/usr/bin/env python3
"""
Check what tools are available from BrightData MCP
"""

from mcp_stdio_client import BrightDataMCPStdioClient
import json
import time

def check_available_tools():
    """Check what tools are available from BrightData MCP"""
    
    print("🔧 Checking available BrightData MCP tools...")
    
    try:
        # Create MCP client
        client = BrightDataMCPStdioClient()
        if not client.start():
            print("❌ Failed to start MCP client")
            return
        
        time.sleep(3)  # Let it initialize
        
        # List available tools
        print("\n📋 Listing available tools...")
        tools_response = client.list_tools()
        if tools_response.success:
            print("✅ Tools retrieved successfully!")
            tools = tools_response.data.get('tools', [])
            
            print(f"\n🔢 Found {len(tools)} tools:")
            print("="*60)
            
            for i, tool in enumerate(tools, 1):
                name = tool.get('name', 'Unknown')
                description = tool.get('description', 'No description')
                
                print(f"\n{i}. {name}")
                print(f"   Description: {description}")
                
                # Show input schema
                if 'inputSchema' in tool:
                    schema = tool['inputSchema']
                    properties = schema.get('properties', {})
                    required = schema.get('required', [])
                    
                    print(f"   Parameters:")
                    for param_name, param_info in properties.items():
                        param_type = param_info.get('type', 'unknown')
                        param_desc = param_info.get('description', '')
                        is_required = '(required)' if param_name in required else '(optional)'
                        
                        print(f"     - {param_name}: {param_type} {is_required}")
                        if param_desc:
                            print(f"       {param_desc}")
                        
                        # Show enum values if available
                        if 'enum' in param_info:
                            print(f"       Options: {param_info['enum']}")
                
                print("-" * 40)
        else:
            print(f"❌ Failed to list tools: {tools_response.error}")
        
        client.stop()
        
    except Exception as e:
        print(f"❌ Error checking tools: {e}")

if __name__ == "__main__":
    check_available_tools()

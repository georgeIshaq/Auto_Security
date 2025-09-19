#!/usr/bin/env python3
"""
Debug script to see what BrightData MCP search actually returns
"""

from mcp_stdio_client import BrightDataMCPStdioClient
import json
import time
import logging

# Enable debug logging
logging.basicConfig(level=logging.DEBUG)

def debug_mcp_search():
    """Debug what the MCP search returns"""
    
    print("🔍 Debugging MCP search results...")
    
    try:
        # Create MCP client
        client = BrightDataMCPStdioClient()
        if not client.start():
            print("❌ Failed to start MCP client")
            return
        
        time.sleep(2)  # Let it initialize
        
        # First, list available tools
        print("\n🔧 Listing available tools...")
        tools_response = client.list_tools()
        if tools_response.success:
            print("✅ Tools list retrieved!")
            print(json.dumps(tools_response.data, indent=2))
        else:
            print(f"❌ Failed to list tools: {tools_response.error}")
        
        # Test search
        print("\n📡 Performing search: 'CVE vulnerability security advisory 2024'")
        search_response = client.search_engine(
            "CVE vulnerability security advisory 2024", 
            max_results=3
        )
        
        if search_response.success:
            print("✅ Search successful!")
            print("\n📋 Full search response structure:")
            print("="*50)
            print(json.dumps(search_response.data, indent=2))
            print("="*50)
            
            # Examine the data structure
            data = search_response.data
            print(f"\n🔍 Response data type: {type(data)}")
            print(f"📊 Response data keys: {list(data.keys()) if isinstance(data, dict) else 'Not a dict'}")
            
            if 'content' in data:
                content = data['content']
                print(f"\n📝 Content type: {type(content)}")
                print(f"📏 Content length: {len(content) if hasattr(content, '__len__') else 'No length'}")
                
                if isinstance(content, list) and len(content) > 0:
                    print(f"\n🔍 First result structure:")
                    first_result = content[0]
                    print(f"Type: {type(first_result)}")
                    if isinstance(first_result, dict):
                        print(f"Keys: {list(first_result.keys())}")
                        for key, value in first_result.items():
                            print(f"  {key}: {type(value)} = {str(value)[:100]}...")
                    else:
                        print(f"Content: {str(first_result)[:200]}...")
            
            # Test scraping one of the URLs if available
            print("\n🌐 Testing page scraping...")
            
            # Try different ways to extract URLs
            urls_to_try = []
            
            if isinstance(data, dict) and 'content' in data:
                content = data['content']
                if isinstance(content, list):
                    for item in content[:2]:  # Try first 2 items
                        if isinstance(item, dict):
                            # Look for URL in various possible fields
                            for url_field in ['url', 'link', 'href', 'source']:
                                if url_field in item:
                                    urls_to_try.append(item[url_field])
                        elif isinstance(item, str) and item.startswith('http'):
                            urls_to_try.append(item)
            
            print(f"🔗 Found {len(urls_to_try)} URLs to test: {urls_to_try}")
            
            for i, url in enumerate(urls_to_try[:1]):  # Test just the first URL
                print(f"\n🌐 Scraping URL {i+1}: {url}")
                try:
                    scrape_response = client.scrape_as_markdown(url)
                    if scrape_response.success:
                        print("✅ Scraping successful!")
                        scraped_data = scrape_response.data
                        print(f"📊 Scraped data type: {type(scraped_data)}")
                        print(f"📊 Scraped data keys: {list(scraped_data.keys()) if isinstance(scraped_data, dict) else 'Not a dict'}")
                        
                        if isinstance(scraped_data, dict) and 'content' in scraped_data:
                            content = scraped_data['content']
                            print(f"📝 Scraped content type: {type(content)}")
                            if isinstance(content, list) and len(content) > 0:
                                text_content = content[0].get('text', '') if isinstance(content[0], dict) else str(content[0])
                                print(f"📄 Text preview (first 300 chars): {text_content[:300]}...")
                            else:
                                print(f"📄 Content preview: {str(content)[:300]}...")
                    else:
                        print(f"❌ Scraping failed: {scrape_response.error}")
                except Exception as e:
                    print(f"❌ Scraping error: {e}")
        else:
            print(f"❌ Search failed: {search_response.error}")
        
        client.stop()
        
    except Exception as e:
        print(f"❌ Debug failed: {e}")

if __name__ == "__main__":
    debug_mcp_search()

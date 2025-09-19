#!/usr/bin/env python3
"""
Simple script to show exactly what we get from BrightData MCP
"""

from mcp_stdio_client import BrightDataMCPStdioClient
import time
import re

def show_brightdata_content():
    print("🔍 Showing raw BrightData content...")
    
    try:
        # Create MCP client
        client = BrightDataMCPStdioClient()
        if not client.start():
            print("❌ Failed to start MCP client")
            return
        
        time.sleep(3)
        
        # Search for CVE
        print("\n📡 Searching for CVE data...")
        search_response = client.search_engine(
            '"CVE-2024" vulnerability details site:nvd.nist.gov', 
            max_results=5
        )
        
        if search_response.success:
            search_content = search_response.data.get('content', [{}])[0].get('text', '')
            print(f"✅ Search successful, found {len(search_content)} characters")
            
            # Extract CVE URLs
            cve_detail_patterns = [
                r'https://nvd\.nist\.gov/vuln/detail/CVE-[0-9]{4}-[0-9]+',
            ]
            
            urls = []
            for pattern in cve_detail_patterns:
                found_urls = re.findall(pattern, search_content)
                urls.extend(found_urls)
            
            urls = list(dict.fromkeys(urls))  # Remove duplicates
            print(f"🔗 Found {len(urls)} CVE URLs: {urls[:3]}")
            
            if urls:
                # Scrape the first URL
                test_url = urls[0]
                print(f"\n🌐 Scraping: {test_url}")
                
                scrape_response = client.scrape_as_markdown(test_url)
                if scrape_response.success:
                    content = scrape_response.data.get('content', [{}])[0].get('text', '')
                    
                    print(f"✅ Scrape successful!")
                    print(f"📄 Content length: {len(content)} characters")
                    print("\n" + "="*80)
                    print("RAW CONTENT FROM BRIGHTDATA:")
                    print("="*80)
                    print(content)
                    print("="*80)
                    
                else:
                    print(f"❌ Scrape failed: {scrape_response.error}")
            else:
                print("❌ No CVE URLs found")
        else:
            print(f"❌ Search failed: {search_response.error}")
        
        client.stop()
        
    except Exception as e:
        print(f"❌ Error: {e}")

if __name__ == "__main__":
    show_brightdata_content()

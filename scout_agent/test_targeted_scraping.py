#!/usr/bin/env python3
"""
Test scraping specific CVE detail pages instead of general database homepages
"""

from mcp_stdio_client import BrightDataMCPStdioClient
import json
import time
import re

def test_targeted_cve_scraping():
    """Test scraping specific CVE detail pages"""
    
    print("🎯 Testing targeted CVE scraping...")
    
    try:
        # Create MCP client
        client = BrightDataMCPStdioClient()
        if not client.start():
            print("❌ Failed to start MCP client")
            return
        
        time.sleep(3)  # Let it initialize
        
        # Try different search strategies
        search_queries = [
            "CVE-2024-12345 site:nvd.nist.gov",  # Specific CVE on NIST
            "CVE-2024 details vulnerability site:cve.mitre.org",  # MITRE CVE database
            '"CVE-2024" vulnerability description',  # Any recent CVE
        ]
        
        for query in search_queries:
            print(f"\n🔍 Testing search: {query}")
            
            search_response = client.search_engine(query, max_results=3)
            if search_response.success:
                search_content = search_response.data.get('content', [{}])[0].get('text', '')
                print(f"✅ Search successful, content length: {len(search_content)}")
                
                # Look for specific CVE detail URLs
                cve_detail_patterns = [
                    r'https://nvd\.nist\.gov/vuln/detail/CVE-[0-9]{4}-[0-9]+',
                    r'https://cve\.mitre\.org/cgi-bin/cvename\.cgi\?name=CVE-[0-9]{4}-[0-9]+',
                    r'https://[^/]+/[^/]*CVE-[0-9]{4}-[0-9]+[^/\s]*',
                ]
                
                found_urls = []
                for pattern in cve_detail_patterns:
                    urls = re.findall(pattern, search_content)
                    found_urls.extend(urls)
                
                print(f"🔗 Found {len(found_urls)} specific CVE URLs:")
                
                # Test scraping the first URL
                if found_urls:
                    test_url = found_urls[0]
                    print(f"\n🌐 Testing scrape of: {test_url}")
                    
                    scrape_response = client.scrape_as_markdown(test_url)
                    if scrape_response.success:
                        content = scrape_response.data.get('content', [{}])[0].get('text', '')
                        print(f"✅ Scrape successful!")
                        print(f"📄 Content length: {len(content)} characters")
                        print(f"📋 Content preview (first 300 chars):")
                        print(content[:300])
                        print("...")
                        
                        # Look for CVE indicators in the content
                        cve_indicators = ['CVE-', 'CVSS', 'vulnerability', 'severity', 'affected']
                        found_indicators = [ind for ind in cve_indicators if ind.lower() in content.lower()]
                        print(f"🎯 CVE indicators found: {found_indicators}")
                        
                        if found_indicators:
                            print("✅ This looks like real CVE content!")
                            return test_url, content
                        else:
                            print("❌ No CVE content detected")
                    else:
                        print(f"❌ Scrape failed: {scrape_response.error}")
                else:
                    print("❌ No specific CVE URLs found")
            else:
                print(f"❌ Search failed: {search_response.error}")
        
        client.stop()
        
    except Exception as e:
        print(f"❌ Error: {e}")
        return None, None

if __name__ == "__main__":
    url, content = test_targeted_cve_scraping()
    if url and content:
        print(f"\n🎉 SUCCESS: Found working CVE URL with real content!")
        print(f"URL: {url}")
        print(f"Content length: {len(content)}")
    else:
        print("\n❌ No working CVE URLs found")

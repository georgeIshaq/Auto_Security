#!/usr/bin/env python3
"""
Check the structured vulnerability data stored in Redis
"""

import redis
import json
from .scout_agent import ScoutAgent
import os
from dotenv import load_dotenv

load_dotenv()

def check_redis_data():
    """Check what data is stored in Redis"""
    
    print("🔍 Checking stored vulnerability data in Redis...")
    
    try:
        # Connect to Redis directly
        redis_client = redis.Redis(host='localhost', port=6379, decode_responses=True)
        
        print(f"✅ Connected to Redis")
        
        # Check what keys exist
        all_keys = redis_client.keys('*')
        print(f"📋 Found {len(all_keys)} keys in Redis")
        
        # Filter for vulnerability-related keys
        vuln_keys = [key for key in all_keys if 'vuln' in key.lower()]
        patch_keys = [key for key in all_keys if 'patch' in key.lower()]
        
        print(f"🦠 Vulnerability keys: {len(vuln_keys)}")
        print(f"🔧 Patch keys: {len(patch_keys)}")
        
        # Show some vulnerability data
        print("\n" + "="*80)
        print("STORED VULNERABILITY DATA:")
        print("="*80)
        
        for i, key in enumerate(vuln_keys[:5]):  # Show first 5
            print(f"\n🔑 Key: {key}")
            data = redis_client.hgetall(key)
            
            if data:
                # Try to extract meaningful fields
                for field, value in data.items():
                    if field in ['text', '_node_content', 'doc_id']:
                        # These might contain our structured data
                        try:
                            # If it's JSON, parse and pretty print
                            if value.startswith('{') and value.endswith('}'):
                                parsed = json.loads(value)
                                print(f"  📄 {field}:")
                                print(json.dumps(parsed, indent=4))
                            else:
                                # Show first 200 chars of text content
                                print(f"  📄 {field}: {value[:200]}...")
                        except:
                            print(f"  📄 {field}: {value[:200]}...")
                    else:
                        print(f"  📊 {field}: {value}")
            print("-" * 60)
        
    except Exception as e:
        print(f"❌ Error connecting to Redis: {e}")
        print("Make sure Redis is running: docker run -d -p 6379:6379 redis/redis-stack")

def check_via_scout_agent():
    """Check data via Scout Agent interface"""
    
    print("\n" + "="*80)
    print("CHECKING VIA SCOUT AGENT:")
    print("="*80)
    
    try:
        # Initialize Scout Agent
        scout = ScoutAgent()
        
        # Query for vulnerabilities
        print("\n🔍 Searching for vulnerabilities...")
        vulns = scout.find_similar_vulnerabilities("vulnerability", top_k=5)
        
        for i, vuln in enumerate(vulns, 1):
            print(f"\n{i}. CVE: {vuln.metadata.get('cve_id', 'Unknown')}")
            print(f"   Severity: {vuln.metadata.get('severity', 'Unknown')}")
            print(f"   CVSS: {vuln.metadata.get('cvss_score', 'Unknown')}")
            print(f"   Type: {vuln.metadata.get('vulnerability_type', 'Unknown')}")
            print(f"   Description: {vuln.text[:200]}...")
            print(f"   Score: {vuln.score}")
        
        # Query for patches
        print("\n🔧 Searching for patches...")
        patches = scout.find_proven_patches("vulnerability", top_k=3)
        
        for i, patch in enumerate(patches, 1):
            print(f"\n{i}. Patch: {patch.metadata.get('patch_id', 'Unknown')}")
            print(f"   Type: {patch.metadata.get('vulnerability_type', 'Unknown')}")
            print(f"   Effectiveness: {patch.metadata.get('effectiveness', 'Unknown')}")
            print(f"   Content: {patch.text[:200]}...")
            print(f"   Score: {patch.score}")
        
        # Get statistics
        print(f"\n📊 Statistics:")
        stats = scout.get_statistics()
        print(json.dumps(stats, indent=2))
        
    except Exception as e:
        print(f"❌ Error with Scout Agent: {e}")

if __name__ == "__main__":
    check_redis_data()
    check_via_scout_agent()

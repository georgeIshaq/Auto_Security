#!/usr/bin/env python3
"""
Clean Redis and repopulate with fresh real vulnerability data
"""

import redis
import time
from .scout_agent import ScoutAgent
import os
from dotenv import load_dotenv

load_dotenv()

def clear_redis():
    """Clear all data from Redis"""
    print("🧹 Clearing Redis database...")
    
    try:
        redis_client = redis.Redis(host='localhost', port=6379, decode_responses=True)
        
        # Get all keys
        all_keys = redis_client.keys('*')
        print(f"📋 Found {len(all_keys)} keys to delete")
        
        if all_keys:
            # Delete all keys
            redis_client.delete(*all_keys)
            print("✅ All Redis data cleared")
        else:
            print("ℹ️  Redis was already empty")
            
    except Exception as e:
        print(f"❌ Error clearing Redis: {e}")
        return False
    
    return True

def repopulate_with_real_data():
    """Repopulate Redis with fresh real vulnerability data"""
    print("\n🌐 Repopulating with fresh real vulnerability data...")
    
    try:
        # Initialize Scout Agent (this will create fresh Redis indices)
        scout = ScoutAgent()
        
        print("✅ Scout Agent initialized with clean Redis")
        
        # Populate with real data only (no mock data)
        print("📡 Fetching real vulnerabilities from web...")
        result = scout.scrape_real_vulnerabilities_via_mcp(limit=5)
        
        if result:
            print(f"✅ Successfully fetched {len(result)} real vulnerabilities")
            
            # Ingest each vulnerability
            for vuln in result:
                scout.ingest_vulnerability(vuln)
                print(f"📥 Ingested: {vuln.cve_id}")
        else:
            print("❌ No real vulnerabilities fetched")
            return False
        
        # Generate some patches for the real vulnerabilities
        print("\n🔧 Generating patches for real vulnerabilities...")
        patches = scout.scrape_security_patches(limit=3)
        
        for patch in patches:
            scout.ingest_patch(patch)
            print(f"📥 Ingested patch: {patch.patch_id}")
        
        print("\n✅ Redis repopulated with clean real data!")
        return True
        
    except Exception as e:
        print(f"❌ Error repopulating data: {e}")
        return False

def verify_clean_data():
    """Verify the clean data"""
    print("\n🔍 Verifying clean data...")
    
    try:
        scout = ScoutAgent()
        
        # Check vulnerabilities
        print("\n📊 Statistics:")
        stats = scout.get_statistics()
        print(f"Status: {stats['status']}")
        print(f"Stores: {stats['stores']}")
        
        # Try to query some vulnerabilities
        print("\n🔍 Sample vulnerabilities:")
        retriever = scout.vuln_index.as_retriever(similarity_top_k=3)
        results = retriever.retrieve("vulnerability")
        
        for i, result in enumerate(results, 1):
            cve_id = result.metadata.get('cve_id', 'Unknown')
            severity = result.metadata.get('severity', 'Unknown')
            vuln_type = result.metadata.get('vulnerability_type', 'Unknown')
            
            print(f"{i}. CVE: {cve_id}")
            print(f"   Severity: {severity}")  
            print(f"   Type: {vuln_type}")
            print(f"   Score: {result.score}")
            print(f"   Preview: {result.text[:100]}...")
            print()
        
        return True
        
    except Exception as e:
        print(f"❌ Error verifying data: {e}")
        return False

if __name__ == "__main__":
    print("🚀 Starting Redis cleanup and repopulation...")
    
    # Step 1: Clear Redis
    if not clear_redis():
        print("❌ Failed to clear Redis, exiting")
        exit(1)
    
    # Step 2: Wait a moment
    print("⏳ Waiting 2 seconds...")
    time.sleep(2)
    
    # Step 3: Repopulate with real data
    if not repopulate_with_real_data():
        print("❌ Failed to repopulate data, exiting")
        exit(1)
    
    # Step 4: Verify
    if verify_clean_data():
        print("✅ SUCCESS: Redis now contains only clean real vulnerability data!")
    else:
        print("❌ FAILED: Issues with verification")

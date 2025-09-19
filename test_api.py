#!/usr/bin/env python3
"""
Test script for the Flask GitHub API
"""

import requests
import json
import os
from typing import Dict, Any

def test_health_endpoint(base_url: str) -> bool:
    """Test the health check endpoint"""
    try:
        response = requests.get(f"{base_url}/health")
        if response.status_code == 200:
            data = response.json()
            print(f"✅ Health check passed: {data}")
            return True
        else:
            print(f"❌ Health check failed: {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ Health check error: {e}")
        return False

def test_repositories_endpoint(base_url: str, token: str, username: str = None) -> bool:
    """Test the repositories endpoint"""
    try:
        params = {
            'token': token,
            'per_page': 5  # Limit to 5 repos for testing
        }
        
        if username:
            params['username'] = username
            
        response = requests.get(f"{base_url}/api/repositories", params=params)
        
        if response.status_code == 200:
            data = response.json()
            print(f"✅ Repositories endpoint passed")
            print(f"   Found {len(data.get('repositories', []))} repositories")
            
            # Show first few repositories
            for i, repo in enumerate(data.get('repositories', [])[:3]):
                print(f"   {i+1}. {repo.get('full_name')} ({repo.get('language', 'No language')})")
            
            return True
        else:
            print(f"❌ Repositories endpoint failed: {response.status_code}")
            try:
                error_data = response.json()
                print(f"   Error: {error_data}")
            except:
                print(f"   Response: {response.text}")
            return False
    except Exception as e:
        print(f"❌ Repositories endpoint error: {e}")
        return False

def main():
    """Main test function"""
    base_url = "http://localhost:5000"
    
    print("🧪 Testing Flask GitHub API")
    print("=" * 50)
    
    # Test health endpoint
    print("\n1. Testing health endpoint...")
    health_ok = test_health_endpoint(base_url)
    
    if not health_ok:
        print("\n❌ Health check failed. Make sure the Flask server is running:")
        print("   python app.py")
        return
    
    # Test repositories endpoint
    print("\n2. Testing repositories endpoint...")
    
    # Get token from environment or prompt user
    token = os.getenv('GITHUB_TOKEN')
    if not token:
        print("❌ GITHUB_TOKEN environment variable not set.")
        print("   Please set it with: export GITHUB_TOKEN=your_token_here")
        print("   Or run: GITHUB_TOKEN=your_token python test_api.py")
        return
    
    # Test with current user's repositories
    repos_ok = test_repositories_endpoint(base_url, token)
    
    if repos_ok:
        print("\n✅ All tests passed! The API is working correctly.")
        print("\n🚀 You can now start the frontend:")
        print("   cd frontend")
        print("   npm run dev")
    else:
        print("\n❌ Repository test failed. Check your GitHub token and try again.")

if __name__ == "__main__":
    main()

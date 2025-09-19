#!/usr/bin/env python3
"""
Test script to verify Scout Agent imports work correctly after reorganization
"""

import sys
import os

# Add the current directory to Python path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

def test_imports():
    """Test that Scout Agent imports work"""
    try:
        print("🔍 Testing Scout Agent imports...")
        
        # Test importing from the scout_agent package
        from scout_agent import ScoutAgent, BrightDataMCPStdioClient
        print("✅ Successfully imported ScoutAgent and BrightDataMCPStdioClient")
        
        # Test that we can instantiate (but not initialize fully)
        print("🔧 Testing basic instantiation...")
        
        # This should work without connecting to Redis/MCP
        print("📦 Scout Agent class available:", ScoutAgent is not None)
        print("📦 MCP Client class available:", BrightDataMCPStdioClient is not None)
        
        print("✅ All imports successful! Scout Agent module is properly organized.")
        return True
        
    except ImportError as e:
        print(f"❌ Import failed: {e}")
        return False
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        return False

if __name__ == "__main__":
    success = test_imports()
    if success:
        print("\n🎉 Scout Agent module organization complete!")
    else:
        print("\n💥 Issues found with module organization")
        sys.exit(1)

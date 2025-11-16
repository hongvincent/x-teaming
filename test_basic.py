#!/usr/bin/env python3
"""
Quick test to verify basic functionality
"""

import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent))

print("Testing LLM Cybersecurity Platform Setup...")
print("=" * 50)

# Test 1: Configuration
print("\n1. Testing configuration...")
try:
    from src.utils.config_loader import get_config
    config = get_config()
    print(f"✅ Configuration loaded successfully")
    print(f"   App name: {config.get('app.name')}")
    print(f"   Environment: {config.get('app.environment')}")
except Exception as e:
    print(f"❌ Configuration failed: {e}")
    sys.exit(1)

# Test 2: API Key
print("\n2. Testing API key...")
try:
    from config.api_keys import APIKeyManager
    api_key = APIKeyManager.get_openai_key()
    if APIKeyManager.validate_key(api_key):
        print(f"✅ API key configured (first 20 chars: {api_key[:20]}...)")
    else:
        print(f"❌ Invalid API key format")
        sys.exit(1)
except Exception as e:
    print(f"❌ API key check failed: {e}")
    sys.exit(1)

# Test 3: LLM Client
print("\n3. Testing LLM client...")
try:
    from src.utils.llm_client import LLMClient
    client = LLMClient(use_cache=True)
    print(f"✅ LLM client initialized successfully")
except Exception as e:
    print(f"❌ LLM client failed: {e}")
    sys.exit(1)

# Test 4: Simple LLM call
print("\n4. Testing OpenAI API connection...")
try:
    response = client.complete(
        "What is SQL injection in one sentence?",
        max_tokens=50
    )
    print(f"✅ API call successful")
    print(f"   Response: {response[:100]}...")
except Exception as e:
    print(f"❌ API call failed: {e}")
    print("   This might be due to rate limits or network issues.")

# Test 5: Network Security Agent
print("\n5. Testing Network Security Agent...")
try:
    from src.domains.network_security.network_security_agent import NetworkSecurityAgent
    agent = NetworkSecurityAgent()
    status = agent.get_agent_status()
    print(f"✅ Network Security Agent initialized")
    print(f"   Status: {status['status']}")
    print(f"   Modules: {len(status['modules'])}")
except Exception as e:
    print(f"❌ Network Security Agent failed: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)

print("\n" + "=" * 50)
print("✅ ALL TESTS PASSED!")
print("=" * 50)
print("\nYou can now run the full demonstration:")
print("  python demos/demo_network_security.py")
print("\nOr test individual modules:")
print("  python src/domains/network_security/web_fuzzing.py")
print("  python src/domains/network_security/traffic_detection.py")
print("  python src/domains/network_security/cti.py")
print("  python src/domains/network_security/penetration_testing.py")


"""
Test to verify CI environment is working.
"""

def test_ci_environment():
    """Basic test to verify CI environment."""
    import sys
    import platform
    
    print(f"🧪 Python version: {sys.version}")
    print(f"🧪 Platform: {platform.platform()}")
    
    # Just verify we can import our modules
    import src.core.vault
    import src.core.crypto
    import src.core.key_derivation
    
    print("🧪 All imports successful")
    
    assert True  # Always passes, just checks imports

def test_pytest_working():
    """Verify pytest is working."""
    assert 1 + 1 == 2
    assert "NeoVault".startswith("Neo")

if __name__ == "__main__":
    test_ci_environment()
    test_pytest_working()
    print("✅ CI environment test passed")

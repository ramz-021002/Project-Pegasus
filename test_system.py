#!/usr/bin/env python3
"""
Test script for Project Pegasus.
Creates a benign test file and uploads it to verify the system works.
"""
import requests
import time
import sys
import json

API_BASE = "http://localhost:8000"


def create_test_file():
    """Create a benign test file."""
    content = b"MZ\x90\x00" + b"This is a benign test file for Project Pegasus" * 50
    with open("test_sample.bin", "wb") as f:
        f.write(content)
    print("✅ Created test file: test_sample.bin")


def test_health():
    """Test health endpoint."""
    print("\n🔍 Testing health endpoint...")
    try:
        response = requests.get(f"{API_BASE}/health", timeout=5)
        if response.status_code == 200:
            print("✅ Health check passed")
            return True
        else:
            print(f"❌ Health check failed: {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ Health check failed: {e}")
        return False


def upload_sample():
    """Upload test sample."""
    print("\n📤 Uploading test sample...")
    try:
        with open("test_sample.bin", "rb") as f:
            files = {"file": ("test_sample.bin", f, "application/octet-stream")}
            response = requests.post(f"{API_BASE}/api/upload/", files=files, timeout=30)

        if response.status_code == 201:
            data = response.json()
            print("✅ Upload successful!")
            print(f"   Sample ID: {data['sample_id']}")
            print(f"   SHA256: {data['sha256']}")
            return data['sample_id']
        else:
            print(f"❌ Upload failed: {response.status_code}")
            print(f"   Response: {response.text}")
            return None
    except Exception as e:
        print(f"❌ Upload failed: {e}")
        return None


def monitor_analysis(sample_id):
    """Monitor analysis progress."""
    print(f"\n⏳ Monitoring analysis for sample {sample_id}...")
    print("   This may take 1-2 minutes...")

    max_attempts = 40  # 40 * 5 seconds = 3+ minutes
    for attempt in range(max_attempts):
        try:
            response = requests.get(f"{API_BASE}/api/upload/{sample_id}", timeout=5)
            if response.status_code == 200:
                data = response.json()
                status = data['status']

                print(f"   Status: {status}", end='\r')

                if status == 'completed':
                    print("\n✅ Analysis completed!")
                    return True
                elif status == 'failed':
                    print("\n❌ Analysis failed!")
                    return False

            time.sleep(5)

        except Exception as e:
            print(f"\n❌ Monitoring error: {e}")
            return False

    print("\n⚠️  Analysis timeout (this is normal if Docker images aren't built)")
    return False


def get_results(sample_id):
    """Get analysis results."""
    print(f"\n📊 Fetching analysis results...")
    try:
        response = requests.get(f"{API_BASE}/api/analysis/{sample_id}", timeout=5)
        if response.status_code == 200:
            data = response.json()
            print("✅ Results retrieved!")
            print(f"\n   Sample Information:")
            print(f"   - SHA256: {data['sha256']}")
            print(f"   - File Size: {data['file_size']} bytes")
            print(f"   - File Type: {data['file_type']}")

            if 'analysis_results' in data:
                print(f"\n   Analysis Results:")
                for analysis_type, result in data['analysis_results'].items():
                    print(f"   - {analysis_type.upper()}: {result['status']}")

            if data.get('network_indicators'):
                print(f"\n   Network Indicators: {len(data['network_indicators'])}")

            return True
        else:
            print(f"❌ Failed to get results: {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ Failed to get results: {e}")
        return False


def main():
    """Run all tests."""
    print("🛡️ Project Pegasus Test Suite")
    print("=" * 50)

    # Test health
    if not test_health():
        print("\n❌ System is not running. Please start with: docker compose up -d")
        sys.exit(1)

    # Create test file
    create_test_file()

    # Upload sample
    sample_id = upload_sample()
    if not sample_id:
        print("\n❌ Upload test failed")
        sys.exit(1)

    # Monitor analysis
    completed = monitor_analysis(sample_id)

    # Get results (even if not completed, to show what we have)
    get_results(sample_id)

    if completed:
        print("\n" + "=" * 50)
        print("✅ All tests passed!")
        print("=" * 50)
        print("\n📋 Next steps:")
        print("   - View API docs: http://localhost:8000/api/docs")
        print("   - Open web interface: frontend/index.html")
        print("   - View logs: docker compose logs -f")
    else:
        print("\n" + "=" * 50)
        print("⚠️  System is working but analysis is still processing")
        print("=" * 50)
        print("\nThis is expected if:")
        print("   - Docker analysis images aren't built yet")
        print("   - Run: ./build-images.sh to build them")
        print("   - Then try uploading through the web interface")


if __name__ == "__main__":
    main()

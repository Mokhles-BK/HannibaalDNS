import anomaly_detection

# Create a fresh AnomalyDetector instance for testing
detector = anomaly_detection.AnomalyDetector()

# Test 1: Verify crash fix with single-label domain
print("Test 1: Single-label domain (localhost)")
try:
    result = detector._check_subdomain_length("localhost")
    if result is False:
        print("PASS: No crash on single-label domain")
    else:
        print("FAIL: Unexpected result for single-label domain")
except Exception as e:
    print(f"FAIL: Unexpected exception: {e}")

# Test 2: Verify long subdomain detection
print("\nTest 2: Long subdomain detection")
long_domain = "a" * 60 + ".com"
try:
    result = detector._check_subdomain_length(long_domain)
    if result is True:
        print("PASS: Correctly detected long subdomain")
    else:
        print("FAIL: Failed to detect long subdomain")
except Exception as e:
    print(f"FAIL: Unexpected exception: {e}")

# Test 3: Verify entropy calculation
print("\nTest 3: Entropy calculation")
try:
    entropy_example = detector._calculate_entropy("example.com")
    entropy_localhost = detector._calculate_entropy("localhost")
    print(f"Entropy for example.com: {entropy_example:.2f}")
    print(f"Entropy for localhost: {entropy_localhost:.2f}")
    if entropy_example > 0 and entropy_localhost > 0:
        print("PASS: Entropy calculated for both domains")
    else:
        print("FAIL: Entropy not calculated correctly")
except Exception as e:
    print(f"FAIL: Unexpected exception: {e}")
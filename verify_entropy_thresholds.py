from anomaly_detection import AnomalyDetector

# Create an AnomalyDetector instance
detector = AnomalyDetector()

# List of common, normal domains to test
test_domains = [
    "google.com",
    "localhost",
    "github.com",
    "amazon.com",
    "microsoft.com",
    "facebook.com",
    "twitter.com",
    "linkedin.com",
    "youtube.com",
    "wikipedia.org",
    "reddit.com",
    "netflix.com",
    "apple.com",
    "instagram.com",
    "stackoverflow.com",
    "medium.com",
    "nytimes.com",
    "bbc.co.uk",
    "cnn.com",
    "washingtonpost.com",
    "nasa.gov",
    "example.com"
]

# Test entropy calculation for each domain
print("=== ENTROPY CALCULATION FOR NORMAL DOMAINS ===")
max_entropy = 0
for domain in test_domains:
    entropy = detector._calculate_entropy(domain)
    print(f"{domain.ljust(20)}: {entropy:.2f}")
    if entropy > max_entropy:
        max_entropy = entropy

# Test the tunneling-style domain from previous tests
tunnel_domain = "aGVsbG93b3JsZHRoaXNpc3R1bm5lbGluZGRhdGEuaW8="
print(f"\n=== TUNNELING-STYLE DOMAIN TEST ===")
tunnel_entropy = detector._calculate_entropy(tunnel_domain)
print(f"{tunnel_domain.ljust(20)}: {tunnel_entropy:.2f}")

# Suggest a new threshold
suggested_threshold = max_entropy + 0.5  # 0.5 above the highest normal domain entropy
print(f"\n=== THRESHOLD SUGGESTION ===")
print(f"Current threshold: {detector.anomaly_thresholds['entropy_threshold']}")
print(f"Highest normal domain entropy: {max_entropy:.2f}")
print(f"Suggested new threshold: {suggested_threshold:.2f}")

# Test localhost specifically
print(f"\n=== LOCALHOST TEST ===")
localhost_entropy = detector._calculate_entropy("localhost")
print(f"localhost: {localhost_entropy:.2f}")
if localhost_entropy < suggested_threshold:
    print("PASS: localhost entropy is below suggested threshold")
else:
    print("FAIL: localhost entropy is above suggested threshold")
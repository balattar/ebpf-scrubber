#!/usr/bin/env python3
"""Test file path resolution"""

import time
import tempfile
import os

print("Testing file path resolution in write monitor")
print("Creating test files in different locations...")
print("-" * 60)

# Test different file locations
test_files = []

# Create temp file
with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
    test_files.append(f.name)
    print(f"Temp file: {f.name}")

# Create file in /tmp
tmp_file = "/tmp/test_monitor.txt"
test_files.append(tmp_file)
print(f"Tmp file: {tmp_file}")

# Wait for monitor to start
time.sleep(1)

# Write test data
for path in test_files:
    print(f"\nWriting to: {path}")
    
    with open(path, 'w') as f:
        f.write("GPS: 45.5 degrees")  # Should flag
    time.sleep(0.5)
    
    with open(path, 'w') as f:
        f.write("Temperature: 200 degrees")  # Should not flag
    time.sleep(0.5)

# Cleanup
for path in test_files:
    try:
        os.unlink(path)
    except:
        pass

print("\nTest complete.")
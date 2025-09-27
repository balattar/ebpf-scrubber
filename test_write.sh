#!/bin/bash
# Test writes to see file paths

echo "Testing file path resolution..."
sleep 2

# Write to different locations
echo "GPS: 45.5 degrees" > /tmp/test1.txt
echo "GPS: -73.2 degrees" > /var/tmp/test2.txt
echo "Temperature: 200" > /tmp/test3.txt

# Write to stdout/stderr (should show pipe or pts)
echo "Value: 10"
echo "Value: 150" >&2

echo "Test complete"
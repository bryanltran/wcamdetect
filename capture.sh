#!/bin/bash
# Simple Blink Camera Data Collection

WIFI_INTERFACE="wlp4s0"
CAPTURE_DIR="data/raw/"
BLINK_SYNC="xx:xx:xx:xx:xx:xx"

mkdir -p "$CAPTURE_DIR"

echo "=== Blink Camera Data Collection ==="
echo "Target: 100 flows of 300 packets each"
echo ""

# Test first
echo "Testing Blink sync module traffic..."
sudo tcpdump -i $WIFI_INTERFACE -c 10 ether host $BLINK_SYNC
echo ""
echo "Did you see packets? Press Enter to continue or Ctrl+C to stop"
read

for i in {1..100}; do
    echo -n "Capturing flow $i/100... "
    
    sudo tcpdump -i $WIFI_INTERFACE -e -nn -tt -v -s 0 \
        -c 300 ether host $BLINK_SYNC \
        -w ${CAPTURE_DIR}/camera_flow${i}.pcap 2>/dev/null
    
    packets=$(tcpdump -r ${CAPTURE_DIR}/camera_flow${i}.pcap 2>/dev/null | wc -l)
    size=$(ls -lh ${CAPTURE_DIR}/camera_flow${i}.pcap | awk '{print $5}')
    
    echo "✓ Got $packets packets ($size)"
    sleep 2
done

echo ""
echo "Done! Captured $(ls ${CAPTURE_DIR}/camera_flow*.pcap | wc -l) flows"
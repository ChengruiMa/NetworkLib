#!/bin/bash

# Script to set Wi-Fi adapter to monitor mode
# Usage: ./set_monitor_mode.sh <interface> <channel>

if [ "$#" -ne 2 ]; then
    echo "Usage: $0 <interface> <channel>"
    echo "Example: $0 wlan0 6"
    exit 1
fi

INTERFACE=$1
CHANNEL=$2

echo "Setting $INTERFACE to monitor mode on channel $CHANNEL..."

# Bring the interface down
sudo ip link set $INTERFACE down

# Set monitor mode
sudo iw dev $INTERFACE set monitor control

# Bring the interface up
sudo ip link set $INTERFACE up

# Set the channel
sudo iw dev $INTERFACE set channel $CHANNEL

# Verify the settings
echo ""
echo "Verifying interface settings:"
iw dev $INTERFACE info

echo ""
echo "Monitor mode setup complete!"
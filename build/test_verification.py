#!/usr/bin/env python3

# Check if existing test files have the right data
import os

files = [
    'xmvrf_message.txt',
    'xmvrf_output.txt', 
    'xmvrf_vk_root.txt',
    'xmvrf_wots_sig_layer0.txt',
    'xmvrf_wots_sig_layer1.txt',
    'xmvrf_auth_path_layer0.txt',
    'xmvrf_auth_path_layer1.txt',
]

print("Checking XM-VRF test files:")
for f in files:
    path = f'/home/agarwalpiyush/BTP-2/XMVRF/build/{f}'
    if os.path.exists(path):
        size = os.path.getsize(path)
        with open(path, 'r') as fh:
            lines = len(fh.readlines())
        print(f"✓ {f:30s} - {size:6d} bytes, {lines} lines")
    else:
        print(f"✗ {f:30s} - NOT FOUND")

# Try to determine the leaf indices used
# Layer 0 has 2^4 = 16 leaves, so index is 0-15
# Layer 1 has 2^4 = 16 leaves, so index is 0-15
# Check if we can infer from the counter

print("\nNote: Layer indices need to be determined from the counter state")
print("With 2 layers of height 4 each:")
print("  Layer 0: leaf_index = counter % 16")
print("  Layer 1: leaf_index = top_layer_index % 16")
print("\nFirst evaluation typically uses: layer0=0, layer1=0")
print("Second evaluation typically uses: layer0=1, layer1=0")

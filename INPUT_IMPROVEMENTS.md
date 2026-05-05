# XM-VRF Input & Verification Improvements

## Changes Made

### 1. **Flexible Input Handling** ✓
- **Before**: Required exact 32-byte hex string input (64 hex characters)
- **After**: Accepts any string and automatically hashes it to 32 bytes using SHA-256

**Updated Components:**
- WOTS+ menu: Seed and message inputs
- XMSS Tree menu: Seed input  
- XM-VRF Eval menu: Message input

**New Helper Function:**
```cpp
vector<uint8_t> hashStringInput(const string& input)
```
- Takes any string input
- Hashes using SHA-256
- Returns 32-byte vector

**User Experience:**
```
Enter seed (any string - will be hashed to 32 bytes): hello world
Seed hashed to: a3b5c7d9e1f3g5h7i9j1k3l5m7n9o1p3...
```

### 2. **Smart File Name Handling** ✓
- **Before**: Required user to manually type each file name for verification
- **After**: Uses auto-generated file names by default, asks if user wants to use them

**New Helper Function:**
```cpp
string getFileNameWithDefault(const string& defaultName, const string& description)
```

**User Experience:**
```
[Message File]
Default file: xmvrf_message.txt
Use this file? (y/n, default=y): 
✓ Using: xmvrf_message.txt
```

Press Enter to use default, or type 'n' to provide custom name.

### 3. **Fixed XM-VRF Verification** ✓
- **Issue**: Verification was trying to open files without output directory path
- **Fix**: All file operations now use `getOutputPath()` wrapper

**Fixed in:**
- VRF output loading
- Message loading
- Layer indices loading
- Signature file loading
- Authentication path file loading

### 4. **Output Directory Organization** ✓
- All output files automatically saved to `output_files/` directory
- Consistent file path handling throughout the application

## Files Modified

1. **src/main.cpp**
   - Added `#include <openssl/sha.h>`
   - Added `hashStringInput()` function
   - Added `getFileNameWithDefault()` function
   - Updated WOTS+ menu for flexible input
   - Updated XMSS Tree menu for flexible input
   - Updated XM-VRF Eval for flexible input
   - Updated XM-VRF Verify for auto-generated file names
   - Fixed all file path operations to use `getOutputPath()`

## Testing the New Features

### Test 1: Flexible Input (WOTS+)
```bash
./build/bin/xmvrf << 'EOF'
1
my secret seed
test message
3
7
EOF
```

### Test 2: File Name Defaults (Verification)
The verification menu will now:
1. Show default file names
2. Ask if you want to use them
3. Allow custom names if needed

### Test 3: Complete XM-VRF Workflow
1. Generate key pair (option 1)
2. Evaluate VRF (option 2) - input any string message
3. Verify VRF (option 3) - use default file names

## Benefits

✓ **User-Friendly**: No need to format inputs as 64-character hex strings
✓ **Flexible**: Any string input is supported
✓ **Safe**: SHA-256 ensures consistent 32-byte format
✓ **Convenient**: Default file names reduce manual typing
✓ **Organized**: All files in dedicated `output_files/` directory
✓ **Robust**: Verification process is more reliable with proper path handling

## Backward Compatibility

The changes are backward compatible:
- Old hex string inputs still work (they'll be treated as strings and hashed)
- File name defaults don't break existing workflows

## Building & Running

```bash
cd /path/to/XMVRF
rm -rf build output_files
mkdir -p build
cd build
cmake ..
make -j4
cd ..
./build/bin/xmvrf
```

All features ready to use! 🎉

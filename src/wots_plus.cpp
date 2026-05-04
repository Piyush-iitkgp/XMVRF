// WOTS+ one-time signature implementation

#include "wots_plus.h"
#include "crypto_utils.h"
#include <cstring>
#include <algorithm>
#include <stdexcept>
#include <fstream>
#include <sstream>
#include <iomanip>

// Apply chain function iteratively
std::vector<uint8_t> ChainFunction(const std::vector<uint8_t>& value, int count) {
    std::vector<uint8_t> current = value;
    for (int i = 0; i < count; i++) {
        current = f_k(current, current);
    }
    return current;
}

// Encode value as base-w digits
std::vector<int> BaseWEncode(const std::vector<uint8_t>& value, int w, int length) {
    if (value.size() != HASH_OUTPUT_SIZE_BYTES) {
        throw std::invalid_argument("BaseWEncode expects 32-byte input");
    }
    
    std::vector<int> digits(length, 0);
    std::vector<uint8_t> temp = value;
    
    for (int i = 0; i < length; i++) {
        int remainder = 0;
        for (int j = 0; j < (int)temp.size(); j++) {
            int dividend = remainder * 256 + temp[j];
            remainder = dividend % w;
            temp[j] = dividend / w;
        }
        digits[i] = remainder;
    }
    
    return digits;
}

// Compute checksum for WOTS+ encoding
std::vector<int> ComputeChecksum(const std::vector<int>& msg_digits, int w) {
    if (w != WOTS_W) {
        throw std::invalid_argument("ChecksumCompute: w parameter mismatch");
    }
    
    int sum = 0;
    for (int digit : msg_digits) {
        if (digit < 0 || digit >= w) {
            throw std::invalid_argument("Checksum: invalid digit value");
        }
        sum += (w - 1 - digit);
    }
    
    std::vector<int> checksum_digits;
    int temp_sum = sum;
    while (temp_sum > 0 && (int)checksum_digits.size() < WOTS_L2) {
        checksum_digits.push_back(temp_sum % w);
        temp_sum /= w;
    }
    
    while ((int)checksum_digits.size() < WOTS_L2) {
        checksum_digits.push_back(0);
    }
    
    checksum_digits.resize(WOTS_L2);
    return checksum_digits;
}

// Hash message to 256 bits
std::vector<uint8_t> HashMessage(const std::vector<uint8_t>& msg) {
    return H1(msg);
}

// Generate WOTS+ key pair from seed
std::pair<WOTSSecretKey, WOTSPublicKey> WOTS_KeyGen(const std::vector<uint8_t>& seed) {
    if (seed.size() != HASH_OUTPUT_SIZE_BYTES) {
        throw std::invalid_argument("WOTS_KeyGen: seed must be 32 bytes");
    }
    
    WOTSSecretKey sk;
    WOTSPublicKey pk;
    
    PRGState prg(seed);
    
    for (int i = 0; i < WOTS_L; i++) {
        sk.sk_components[i] = PRG_generate(prg);
        pk.pk_components[i] = ChainFunction(sk.sk_components[i], WOTS_W - 1);
    }
    
    return {sk, pk};
}

// Sign message with WOTS+ secret key
WOTSSignature WOTS_Sign(const WOTSSecretKey& sk, const std::vector<uint8_t>& msg) {
    if (msg.size() != HASH_OUTPUT_SIZE_BYTES) {
        throw std::invalid_argument("WOTS_Sign: message must be 32 bytes");
    }
    
    WOTSSignature sig;
    
    auto msg_digits = BaseWEncode(msg, WOTS_W, WOTS_L1);
    auto checksum_digits = ComputeChecksum(msg_digits, WOTS_W);
    
    std::vector<int> all_digits;
    all_digits.insert(all_digits.end(), msg_digits.begin(), msg_digits.end());
    all_digits.insert(all_digits.end(), checksum_digits.begin(), checksum_digits.end());
    
    if ((int)all_digits.size() != WOTS_L) {
        throw std::runtime_error("WOTS_Sign: digit count mismatch");
    }
    
    for (int i = 0; i < WOTS_L; i++) {
        int digit = all_digits[i];
        if (digit < 0 || digit >= WOTS_W) {
            throw std::runtime_error("WOTS_Sign: invalid digit value");
        }
        sig.sig_components[i] = ChainFunction(sk.sk_components[i], digit);
    }
    
    return sig;
}

// Verify WOTS+ signature
bool WOTS_Verify(const WOTSPublicKey& pk,
                 const std::vector<uint8_t>& msg,
                 const WOTSSignature& sig) {
    if (msg.size() != HASH_OUTPUT_SIZE_BYTES) {
        return false;
    }
    
    auto msg_digits = BaseWEncode(msg, WOTS_W, WOTS_L1);
    auto checksum_digits = ComputeChecksum(msg_digits, WOTS_W);
    
    std::vector<int> all_digits;
    all_digits.insert(all_digits.end(), msg_digits.begin(), msg_digits.end());
    all_digits.insert(all_digits.end(), checksum_digits.begin(), checksum_digits.end());
    
    for (int i = 0; i < WOTS_L; i++) {
        int digit = all_digits[i];
        if (digit < 0 || digit >= WOTS_W) {
            return false;
        }
        
        int remaining_chain = WOTS_W - 1 - digit;
        auto reconstructed = ChainFunction(sig.sig_components[i], remaining_chain);
        
        if (reconstructed != pk.pk_components[i]) {
            return false;
        }
    }
    
    return true;
}

// Get WOTS+ signature size in bytes
size_t WOTS_SignatureSize() {
    return WOTS_L * HASH_OUTPUT_SIZE_BYTES;
}

// Get number of WOTS+ signature components
int WOTS_ComponentCount() {
    return WOTS_L;
}

// Save WOTS+ signature to file (space-separated hex format)
void WOTS_SaveSignatureToFile(const WOTSSignature& sig, const std::string& filename) {
    std::ofstream file(filename);
    if (!file.is_open()) {
        throw std::runtime_error("Failed to open file for writing: " + filename);
    }
    
    for (int i = 0; i < WOTS_L; i++) {
        for (int j = 0; j < HASH_OUTPUT_SIZE_BYTES; j++) {
            file << std::hex << std::setfill('0') << std::setw(2) 
                 << static_cast<int>(sig.sig_components[i][j]);
        }
        if (i < WOTS_L - 1) {
            file << " ";
        }
    }
    file << std::endl;
    file.close();
}

// Load WOTS+ signature from file (space-separated hex format)
WOTSSignature WOTS_LoadSignatureFromFile(const std::string& filename) {
    std::ifstream file(filename);
    if (!file.is_open()) {
        throw std::runtime_error("Failed to open file for reading: " + filename);
    }
    
    WOTSSignature sig;
    std::string line;
    std::getline(file, line);
    file.close();
    
    std::istringstream stream(line);
    std::string component;
    int idx = 0;
    
    while (stream >> component && idx < WOTS_L) {
        if (component.length() != 2 * HASH_OUTPUT_SIZE_BYTES) {
            throw std::runtime_error("Invalid component size in file");
        }
        
        for (int j = 0; j < HASH_OUTPUT_SIZE_BYTES; j++) {
            std::string byteStr = component.substr(j * 2, 2);
            sig.sig_components[idx][j] = static_cast<uint8_t>(
                std::strtol(byteStr.c_str(), nullptr, 16)
            );
        }
        idx++;
    }
    
    if (idx != WOTS_L) {
        throw std::runtime_error("Expected " + std::to_string(WOTS_L) + 
                                 " components, got " + std::to_string(idx));
    }
    
    return sig;
}

// Save WOTS+ public key to file (space-separated hex format)
void WOTS_SavePublicKeyToFile(const WOTSPublicKey& pk, const std::string& filename) {
    std::ofstream file(filename);
    if (!file.is_open()) {
        throw std::runtime_error("Failed to open file for writing: " + filename);
    }
    
    for (int i = 0; i < WOTS_L; i++) {
        for (int j = 0; j < HASH_OUTPUT_SIZE_BYTES; j++) {
            file << std::hex << std::setfill('0') << std::setw(2) 
                 << static_cast<int>(pk.pk_components[i][j]);
        }
        if (i < WOTS_L - 1) {
            file << " ";
        }
    }
    file << std::endl;
    file.close();
}

// Load WOTS+ public key from file (space-separated hex format)
WOTSPublicKey WOTS_LoadPublicKeyFromFile(const std::string& filename) {
    std::ifstream file(filename);
    if (!file.is_open()) {
        throw std::runtime_error("Failed to open file for reading: " + filename);
    }
    
    WOTSPublicKey pk;
    std::string line;
    std::getline(file, line);
    file.close();
    
    std::istringstream stream(line);
    std::string component;
    int idx = 0;
    
    while (stream >> component && idx < WOTS_L) {
        if (component.length() != 2 * HASH_OUTPUT_SIZE_BYTES) {
            throw std::runtime_error("Invalid component size in file");
        }
        
        for (int j = 0; j < HASH_OUTPUT_SIZE_BYTES; j++) {
            std::string byteStr = component.substr(j * 2, 2);
            pk.pk_components[idx][j] = static_cast<uint8_t>(
                std::strtol(byteStr.c_str(), nullptr, 16)
            );
        }
        idx++;
    }
    
    if (idx != WOTS_L) {
        throw std::runtime_error("Expected " + std::to_string(WOTS_L) + 
                                 " components, got " + std::to_string(idx));
    }
    
    return pk;
}

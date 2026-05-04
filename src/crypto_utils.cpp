// Core cryptographic primitives using OpenSSL

#include "crypto_utils.h"
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <iomanip>
#include <sstream>
#include <cstring>

// Compress two 256-bit hashes to 256-bit output
std::vector<uint8_t> H(const std::vector<uint8_t>& left,
                       const std::vector<uint8_t>& right) {
    if (left.size() != HASH_OUTPUT_SIZE_BYTES || 
        right.size() != HASH_OUTPUT_SIZE_BYTES) {
        throw std::invalid_argument("H() expects two 32-byte inputs");
    }
    
    std::vector<uint8_t> combined;
    combined.insert(combined.end(), left.begin(), left.end());
    combined.insert(combined.end(), right.begin(), right.end());
    
    unsigned char hash_output[EVP_MAX_MD_SIZE];
    unsigned int hash_len = 0;
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(mdctx, EVP_sha256(), nullptr);
    EVP_DigestUpdate(mdctx, combined.data(), combined.size());
    EVP_DigestFinal_ex(mdctx, hash_output, &hash_len);
    EVP_MD_CTX_free(mdctx);
    
    return std::vector<uint8_t>(hash_output, 
                                hash_output + HASH_OUTPUT_SIZE_BYTES);
}

// Variable-length input to 256-bit hash
std::vector<uint8_t> H1(const std::vector<uint8_t>& data) {
    const std::vector<uint8_t> domain_sep = string_to_bytes("H1");
    
    std::vector<uint8_t> input;
    input.insert(input.end(), domain_sep.begin(), domain_sep.end());
    input.insert(input.end(), data.begin(), data.end());
    
    unsigned char hash_output[EVP_MAX_MD_SIZE];
    unsigned int hash_len = 0;
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(mdctx, EVP_sha256(), nullptr);
    EVP_DigestUpdate(mdctx, input.data(), input.size());
    EVP_DigestFinal_ex(mdctx, hash_output, &hash_len);
    EVP_MD_CTX_free(mdctx);
    
    return std::vector<uint8_t>(hash_output,
                                hash_output + HASH_OUTPUT_SIZE_BYTES);
}

// Initialize PRG state with seed
PRGState::PRGState(const std::vector<uint8_t>& seed) {
    if (seed.size() != HASH_OUTPUT_SIZE_BYTES) {
        throw std::invalid_argument("PRG seed must be 32 bytes");
    }
    state = seed;
    counter = 0;
}

// Generate next PRG output with counter mode
std::vector<uint8_t> PRG_generate(PRGState& prg_state) {
    uint64_t counter_for_output = prg_state.counter;
    
    uint8_t counter_bytes[8];
    for (int i = 7; i >= 0; i--) {
        counter_bytes[i] = static_cast<uint8_t>(counter_for_output & 0xFF);
        counter_for_output >>= 8;
    }
    
    unsigned char output[HASH_OUTPUT_SIZE_BYTES];
    unsigned int output_len;
    HMAC(EVP_sha256(), 
         prg_state.state.data(), prg_state.state.size(),
         counter_bytes, sizeof(counter_bytes),
         output, &output_len);
    
    uint64_t counter_for_state = prg_state.counter + 1;
    uint8_t state_counter_bytes[8];
    for (int i = 7; i >= 0; i--) {
        state_counter_bytes[i] = static_cast<uint8_t>(counter_for_state & 0xFF);
        counter_for_state >>= 8;
    }
    
    unsigned char new_state[HASH_OUTPUT_SIZE_BYTES];
    unsigned int state_len;
    HMAC(EVP_sha256(),
         prg_state.state.data(), prg_state.state.size(),
         state_counter_bytes, sizeof(state_counter_bytes),
         new_state, &state_len);
    
    prg_state.state.assign(new_state, new_state + HASH_OUTPUT_SIZE_BYTES);
    prg_state.counter += 2;
    
    return std::vector<uint8_t>(output, output + HASH_OUTPUT_SIZE_BYTES);
}

// Keyed hash function with domain separation
std::vector<uint8_t> f_k(const std::vector<uint8_t>& key,
                         const std::vector<uint8_t>& input) {
    if (key.size() != HASH_OUTPUT_SIZE_BYTES) {
        throw std::invalid_argument("f_k key must be 32 bytes");
    }
    if (input.size() != HASH_OUTPUT_SIZE_BYTES) {
        throw std::invalid_argument("f_k input must be 32 bytes");
    }
    
    const std::vector<uint8_t> domain_sep = string_to_bytes("f_k");
    
    std::vector<uint8_t> hmac_input;
    hmac_input.insert(hmac_input.end(), domain_sep.begin(), domain_sep.end());
    hmac_input.insert(hmac_input.end(), input.begin(), input.end());
    
    unsigned char hash_output[HASH_OUTPUT_SIZE_BYTES];
    unsigned int hash_len;
    HMAC(EVP_sha256(),
         key.data(), key.size(),
         hmac_input.data(), hmac_input.size(),
         hash_output, &hash_len);
    
    return std::vector<uint8_t>(hash_output,
                                hash_output + HASH_OUTPUT_SIZE_BYTES);
}

// XOR two byte arrays
std::vector<uint8_t> xor_bytes(const std::vector<uint8_t>& a,
                               const std::vector<uint8_t>& b) {
    if (a.size() != b.size()) {
        throw std::invalid_argument("xor_bytes requires equal-length inputs");
    }
    
    std::vector<uint8_t> result;
    result.reserve(a.size());
    
    for (size_t i = 0; i < a.size(); i++) {
        result.push_back(a[i] ^ b[i]);
    }
    
    return result;
}

// Concatenate two byte arrays
std::vector<uint8_t> concat_bytes(const std::vector<uint8_t>& a,
                                  const std::vector<uint8_t>& b) {
    std::vector<uint8_t> result;
    result.reserve(a.size() + b.size());
    result.insert(result.end(), a.begin(), a.end());
    result.insert(result.end(), b.begin(), b.end());
    return result;
}

// Convert string to bytes
std::vector<uint8_t> string_to_bytes(const std::string& s) {
    return std::vector<uint8_t>(s.begin(), s.end());
}

// Convert bytes to hex string
std::string bytes_to_hex(const std::vector<uint8_t>& data) {
    std::ostringstream oss;
    for (uint8_t byte : data) {
        oss << std::hex << std::setw(2) << std::setfill('0') 
            << static_cast<int>(byte);
    }
    return oss.str();
}

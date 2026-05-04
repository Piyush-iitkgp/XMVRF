// Core cryptographic utilities for XM-VRF

#ifndef CRYPTO_UTILS_H
#define CRYPTO_UTILS_H

#include <cstdint>
#include <vector>
#include <string>

const int HASH_OUTPUT_SIZE_BYTES = 32;
const int HASH_OUTPUT_SIZE_BITS = 256;

// Compress two 256-bit hashes to one 256-bit hash using SHA-256
std::vector<uint8_t> H(const std::vector<uint8_t>& left,
                       const std::vector<uint8_t>& right);

// Variable-length input to 256-bit hash output
std::vector<uint8_t> H1(const std::vector<uint8_t>& data);

// Stateful pseudorandom generator
struct PRGState {
    std::vector<uint8_t> state;
    uint64_t counter;
    PRGState(const std::vector<uint8_t>& seed);
};

// Generate next pseudorandom output from PRG state
std::vector<uint8_t> PRG_generate(PRGState& prg_state);

// Keyed hash function family
std::vector<uint8_t> f_k(const std::vector<uint8_t>& key,
                         const std::vector<uint8_t>& input);

// XOR two byte arrays
std::vector<uint8_t> xor_bytes(const std::vector<uint8_t>& a,
                               const std::vector<uint8_t>& b);

// Concatenate two byte arrays
std::vector<uint8_t> concat_bytes(const std::vector<uint8_t>& a,
                                  const std::vector<uint8_t>& b);

// Convert string to bytes
std::vector<uint8_t> string_to_bytes(const std::string& s);

// Convert bytes to hex string
std::string bytes_to_hex(const std::vector<uint8_t>& data);

#endif // CRYPTO_UTILS_H

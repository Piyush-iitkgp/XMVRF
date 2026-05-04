// WOTS+ one-time signature scheme

#ifndef WOTS_PLUS_H
#define WOTS_PLUS_H

#include "crypto_utils.h"
#include <vector>
#include <cstdint>

// WOTS+ parameters
const int WOTS_W = 16;
const int WOTS_M = 256;
const int WOTS_L1 = 64;
const int WOTS_L2 = 3;
const int WOTS_L = WOTS_L1 + WOTS_L2;

// WOTS+ secret key with l components
struct WOTSSecretKey {
    std::vector<std::vector<uint8_t>> sk_components;
    WOTSSecretKey() : sk_components(WOTS_L) {
        for (int i = 0; i < WOTS_L; i++) {
            sk_components[i].resize(HASH_OUTPUT_SIZE_BYTES, 0);
        }
    }
};

// WOTS+ public key with l components
struct WOTSPublicKey {
    std::vector<std::vector<uint8_t>> pk_components;
    WOTSPublicKey() : pk_components(WOTS_L) {
        for (int i = 0; i < WOTS_L; i++) {
            pk_components[i].resize(HASH_OUTPUT_SIZE_BYTES, 0);
        }
    }
};

// WOTS+ signature with l components
struct WOTSSignature {
    std::vector<std::vector<uint8_t>> sig_components;
    WOTSSignature() : sig_components(WOTS_L) {
        for (int i = 0; i < WOTS_L; i++) {
            sig_components[i].resize(HASH_OUTPUT_SIZE_BYTES, 0);
        }
    }
};

// Generate WOTS+ key pair from seed
std::pair<WOTSSecretKey, WOTSPublicKey> WOTS_KeyGen(const std::vector<uint8_t>& seed);

// Sign message with WOTS+ secret key
WOTSSignature WOTS_Sign(const WOTSSecretKey& sk, const std::vector<uint8_t>& msg);

// Verify WOTS+ signature
bool WOTS_Verify(const WOTSPublicKey& pk,
                 const std::vector<uint8_t>& msg,
                 const WOTSSignature& sig);

// Apply chain function iteratively
std::vector<uint8_t> ChainFunction(const std::vector<uint8_t>& value, int count);

// Encode value as base-w digits
std::vector<int> BaseWEncode(const std::vector<uint8_t>& value, int w, int length);

// Compute checksum for WOTS+ encoding
std::vector<int> ComputeChecksum(const std::vector<int>& msg_digits, int w);

// Hash message to 256 bits
std::vector<uint8_t> HashMessage(const std::vector<uint8_t>& msg);

// Get WOTS+ signature size in bytes
size_t WOTS_SignatureSize();

// Get number of WOTS+ signature components
int WOTS_ComponentCount();

// Save WOTS+ signature to file (space-separated hex format)
void WOTS_SaveSignatureToFile(const WOTSSignature& sig, const std::string& filename);

// Load WOTS+ signature from file (space-separated hex format)
WOTSSignature WOTS_LoadSignatureFromFile(const std::string& filename);

// Save WOTS+ public key to file (space-separated hex format)
void WOTS_SavePublicKeyToFile(const WOTSPublicKey& pk, const std::string& filename);

// Load WOTS+ public key from file (space-separated hex format)
WOTSPublicKey WOTS_LoadPublicKeyFromFile(const std::string& filename);

#endif // WOTS_PLUS_H

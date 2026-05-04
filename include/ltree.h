#ifndef LTREE_H
#define LTREE_H

#include "crypto_utils.h"
#include "wots_plus.h"
#include <vector>
#include <cstdint>
#include <cmath>

// L-tree parameters
const int LTREE_NUM_LEAVES = WOTS_L;
const int LTREE_NUM_BITMASKS = static_cast<int>(std::ceil(std::log2(LTREE_NUM_LEAVES)));

// L-Tree node
struct LTreeNode {
    std::vector<uint8_t> value;
    size_t height;
    
    LTreeNode() : value(HASH_OUTPUT_SIZE_BYTES, 0), height(0) {}
    LTreeNode(const std::vector<uint8_t>& val, size_t h) : value(val), height(h) {}
};

// L-Tree input with public key components and bitmasks
struct LTreeInput {
    std::vector<std::vector<uint8_t>> pk_components;
    std::vector<std::vector<uint8_t>> bitmasks;
    
    LTreeInput() : pk_components(LTREE_NUM_LEAVES, 
                                 std::vector<uint8_t>(HASH_OUTPUT_SIZE_BYTES, 0)),
                   bitmasks(LTREE_NUM_BITMASKS,
                           std::vector<uint8_t>(2 * HASH_OUTPUT_SIZE_BYTES, 0)) {}
};

// L-Tree output
struct LTreeOutput {
    std::vector<uint8_t> root;
    
    LTreeOutput() : root(HASH_OUTPUT_SIZE_BYTES, 0) {}
};

// Compute L-Tree root from WOTS+ public key components
LTreeOutput LTree(const LTreeInput& input);

// Convenience overload taking vectors directly
std::vector<uint8_t> LTree(const std::vector<std::vector<uint8_t>>& pk_components,
                           const std::vector<std::vector<uint8_t>>& bitmasks);

// Save L-Tree root to file
void LTree_SaveRootToFile(const std::vector<uint8_t>& root, const std::string& filename);

// Load L-Tree root from file
std::vector<uint8_t> LTree_LoadRootFromFile(const std::string& filename);

// Compute L-Tree root from WOTS+ public key file
std::vector<uint8_t> LTree_ComputeFromPublicKeyFile(const std::string& pk_filename);

// Verify L-Tree root from WOTS+ public key file
bool LTree_VerifyFromPublicKeyFile(const std::string& pk_filename, 
                                   const std::string& root_filename);

// Reconstruct WOTS+ public key from WOTS+ signature file and message
WOTSPublicKey LTree_ReconstructPublicKeyFromSignature(const std::string& sig_filename,
                                                       const std::vector<uint8_t>& message);

// Reconstruct WOTS+ public key from WOTS+ signature (struct) and message
WOTSPublicKey LTree_ReconstructPublicKeyFromSignatureStruct(const WOTSSignature& sig,
                                                            const std::vector<uint8_t>& message);

// Verify XMSS using all components (signature, auth path, root, message)
bool XMSS_VerifyComplete(const std::string& root_filename,
                         const std::string& sig_filename,
                         const std::string& auth_path_filename,
                         const std::vector<uint8_t>& message,
                         size_t tree_height);

#endif // LTREE_H

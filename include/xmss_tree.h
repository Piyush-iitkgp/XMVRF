#ifndef XMSS_TREE_H
#define XMSS_TREE_H

#include "crypto_utils.h"
#include "wots_plus.h"
#include "ltree.h"
#include <vector>
#include <stack>
#include <cstdint>
#include <cmath>

// XMSS tree parameters
const int XMSS_DEFAULT_HEIGHT = 10;
const int XMSS_AUTH_PATH_LENGTH = XMSS_DEFAULT_HEIGHT;

// XMSS tree node
struct XMSSTreeNode {
    std::vector<uint8_t> value;
    size_t height;
    
    XMSSTreeNode() : value(HASH_OUTPUT_SIZE_BYTES, 0), height(0) {}
    XMSSTreeNode(const std::vector<uint8_t>& val, size_t h) : value(val), height(h) {}
};

// XMSS public key with root and bitmasks
struct XMSSPublicKey {
    std::vector<uint8_t> root;
    std::vector<std::vector<uint8_t>> bitmasks;
    std::vector<std::vector<uint8_t>> ltree_bitmasks;
    
    XMSSPublicKey() : root(HASH_OUTPUT_SIZE_BYTES, 0),
                      bitmasks(XMSS_DEFAULT_HEIGHT, 
                               std::vector<uint8_t>(2 * HASH_OUTPUT_SIZE_BYTES, 0)),
                      ltree_bitmasks(LTREE_NUM_BITMASKS,
                                    std::vector<uint8_t>(2 * HASH_OUTPUT_SIZE_BYTES, 0)) {}
};

// XMSS secret key with seed and tree height
struct XMSSSecretKey {
    std::vector<uint8_t> seed;
    size_t tree_height;
    std::vector<std::vector<uint8_t>> ltree_bitmasks;
    std::vector<std::vector<uint8_t>> xmss_bitmasks;
    
    XMSSSecretKey(size_t h = XMSS_DEFAULT_HEIGHT)
        : tree_height(h),
          ltree_bitmasks(LTREE_NUM_BITMASKS,
                        std::vector<uint8_t>(2 * HASH_OUTPUT_SIZE_BYTES, 0)),
          xmss_bitmasks(h,
                       std::vector<uint8_t>(2 * HASH_OUTPUT_SIZE_BYTES, 0)) {}
};

// XMSS signature with index, WOTS sig, and authentication path
struct XMSSSignature {
    size_t index;
    WOTSSignature wots_sig;
    std::vector<std::vector<uint8_t>> auth_path;
    
    XMSSSignature(size_t h = XMSS_DEFAULT_HEIGHT)
        : index(0), auth_path(h, std::vector<uint8_t>(HASH_OUTPUT_SIZE_BYTES, 0)) {}
};

// XMSS tree class using TreeHash algorithm
class XMSSTree {
private:
    std::stack<XMSSTreeNode> nodeStack;
    std::vector<std::vector<uint8_t>> bitmasks;

public:
    // Constructor
    XMSSTree(size_t h, const std::vector<std::vector<uint8_t>>& tree_bitmasks);
    
    // Add new leaf using TreeHash algorithm
    void TreeHash(const XMSSTreeNode& leaf);
    
    // Get final root
    std::vector<uint8_t> GetRoot();
    
    // Reset tree
    void Reset();
};

// Initialize XMSS parameters
void XMSS_Setup(size_t h);

// Generate XMSS key pair
std::pair<XMSSSecretKey, XMSSPublicKey> XMSS_KeyGen(size_t h = XMSS_DEFAULT_HEIGHT);

// Sign message using XMSS
XMSSSignature XMSS_Sign(const XMSSSecretKey& sk, size_t index,
                        const std::vector<uint8_t>& message);

// Build XMSS tree and get root and authentication path for given index
struct XMSSTreeOutput {
    std::vector<uint8_t> root;
    std::vector<std::vector<uint8_t>> auth_path;
    WOTSSignature wots_sig;
    size_t index;
    
    XMSSTreeOutput(size_t h = XMSS_DEFAULT_HEIGHT)
        : root(HASH_OUTPUT_SIZE_BYTES, 0), 
          auth_path(h, std::vector<uint8_t>(HASH_OUTPUT_SIZE_BYTES, 0)),
          index(0) {}
};

// Build full XMSS tree and return root with authentication path for specific index
XMSSTreeOutput XMSS_BuildTree(const std::vector<uint8_t>& seed, 
                               size_t tree_height,
                               size_t leaf_index,
                               const std::vector<std::vector<uint8_t>>& xmss_bitmasks,
                               const std::vector<std::vector<uint8_t>>& ltree_bitmasks);

#endif // XMSS_TREE_H
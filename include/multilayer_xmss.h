#ifndef MULTILAYER_XMSS_H
#define MULTILAYER_XMSS_H

#include "xmss_tree.h"
#include "wots_plus.h"
#include "ltree.h"
#include <vector>
#include <cstdint>

// Multi-layer XMSS parameters
const int DEFAULT_NUM_LAYERS = 2;
const int DEFAULT_TOTAL_HEIGHT = 8;
const int DEFAULT_LAYER_HEIGHT = DEFAULT_TOTAL_HEIGHT / DEFAULT_NUM_LAYERS;

// XMSS state for efficient authentication path computation
struct XMSSState {
    std::vector<std::vector<uint8_t>> Store;
    std::vector<std::vector<uint8_t>> Stock;
    std::vector<std::vector<std::vector<uint8_t>>> Cache;
    std::vector<std::vector<uint8_t>> Auth;
    
    XMSSState(size_t height = DEFAULT_LAYER_HEIGHT);
    void Reset(size_t height);
};

// Secret key for multi-layer XMSS
struct MultiLayerXMSSSecretKey {
    size_t d;
    size_t h_prime;
    std::vector<std::vector<uint8_t>> Scur;
    std::vector<std::vector<uint8_t>> Snext;
    std::vector<XMSSState> states_cur;
    std::vector<XMSSState> states_next;
    std::vector<std::vector<std::vector<uint8_t>>> xmss_bitmasks;
    std::vector<std::vector<std::vector<uint8_t>>> ltree_bitmasks;
    std::vector<WOTSSignature> layer_signatures;
    uint64_t counter;
    uint64_t top_layer_index;
    
    MultiLayerXMSSSecretKey(size_t num_layers = DEFAULT_NUM_LAYERS,
                             size_t layer_height = DEFAULT_LAYER_HEIGHT);
};

// Public key (verification key) for multi-layer XMSS
struct MultiLayerXMSSPublicKey {
    std::vector<uint8_t> root;
    std::vector<std::vector<std::vector<uint8_t>>> xmss_bitmasks;
    std::vector<std::vector<std::vector<uint8_t>>> ltree_bitmasks;
    size_t d;
    size_t h_prime;
    
    MultiLayerXMSSPublicKey(size_t num_layers = DEFAULT_NUM_LAYERS,
                             size_t layer_height = DEFAULT_LAYER_HEIGHT);
};

// Proof from multi-layer XMSS evaluation
struct MultiLayerXMSSProof {
    std::vector<WOTSSignature> wots_sigs;
    std::vector<std::vector<std::vector<uint8_t>>> auth_paths;
    size_t d;
    
    MultiLayerXMSSProof(size_t num_layers = DEFAULT_NUM_LAYERS,
                         size_t layer_height = DEFAULT_LAYER_HEIGHT);
    
    // Serialize and deserialize
    std::vector<uint8_t> Serialize() const;
    static MultiLayerXMSSProof Deserialize(const std::vector<uint8_t>& data);
};

// Generate multi-layer XMSS key pair
std::pair<MultiLayerXMSSSecretKey, MultiLayerXMSSPublicKey>
MultiXMSS_KeyGen(size_t num_layers = DEFAULT_NUM_LAYERS,
                 size_t layer_height = DEFAULT_LAYER_HEIGHT);

// Evaluate multi-layer XMSS (signing equivalent)
MultiLayerXMSSProof MultiXMSS_Eval(MultiLayerXMSSSecretKey& sk,
                                    const std::vector<uint8_t>& message);

// Evaluate multi-layer XMSS with specific indices for each layer
MultiLayerXMSSProof MultiXMSS_EvalWithIndices(MultiLayerXMSSSecretKey& sk,
                                               const std::vector<size_t>& layer_indices);

// Verify multi-layer XMSS proof using root, signatures, authentication paths, and leaf indices
bool MultiXMSS_VerifyComplete(const MultiLayerXMSSPublicKey& pk,
                               const MultiLayerXMSSProof& proof,
                               const std::vector<uint8_t>& message,
                               const std::vector<size_t>& layer_indices);

#endif // MULTILAYER_XMSS_H

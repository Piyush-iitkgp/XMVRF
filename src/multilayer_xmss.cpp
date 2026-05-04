// Multi-layer XMSS implementation

#include "multilayer_xmss.h"
#include "crypto_utils.h"
#include "xmss_tree.h"
#include "wots_plus.h"
#include "ltree.h"
#include <stdexcept>
#include <cmath>
#include <cstring>
#include <iostream>

// Initialize XMSS state
XMSSState::XMSSState(size_t height) {
    Reset(height);
}

void XMSSState::Reset(size_t height) {
    Store.resize(height);
    for (auto& node : Store) {
        node.resize(HASH_OUTPUT_SIZE_BYTES, 0);
    }
    
    Stock.resize(height);
    for (auto& node : Stock) {
        node.resize(HASH_OUTPUT_SIZE_BYTES, 0);
    }
    
    Cache.resize(height);
    for (auto& level : Cache) {
        level.resize(height);
        for (auto& node : level) {
            node.resize(HASH_OUTPUT_SIZE_BYTES, 0);
        }
    }
    
    Auth.resize(height);
    for (auto& node : Auth) {
        node.resize(HASH_OUTPUT_SIZE_BYTES, 0);
    }
}

// ============================================================================
// MultiLayerXMSSSecretKey Constructor
// ============================================================================

MultiLayerXMSSSecretKey::MultiLayerXMSSSecretKey(size_t num_layers,
                                                 size_t layer_height)
    : d(num_layers), h_prime(layer_height), counter(1), top_layer_index(0) {
    
    // MODIFIED: Added initialization of top_layer_index for 2-layer looping design
    
    // Initialize seed vectors for current and next trees
    Scur.resize(d);
    Snext.resize(d);
    for (size_t i = 0; i < d; i++) {
        Scur[i].resize(HASH_OUTPUT_SIZE_BYTES, 0);
        Snext[i].resize(HASH_OUTPUT_SIZE_BYTES, 0);
    }
    
    // Initialize states for each layer
    states_cur.resize(d);
    states_next.resize(d);
    for (size_t i = 0; i < d; i++) {
        states_cur[i] = XMSSState(h_prime);
        states_next[i] = XMSSState(h_prime);
    }
    
    // Initialize bitmasks for XMSS trees
    xmss_bitmasks.resize(d);
    for (size_t i = 0; i < d; i++) {
        xmss_bitmasks[i].resize(h_prime);
        for (size_t j = 0; j < h_prime; j++) {
            xmss_bitmasks[i][j].resize(2 * HASH_OUTPUT_SIZE_BYTES, 0);
        }
    }
    
    // Initialize bitmasks for L-Tree
    ltree_bitmasks.resize(d);
    for (size_t i = 0; i < d; i++) {
        ltree_bitmasks[i].resize(LTREE_NUM_BITMASKS);
        for (size_t j = 0; j < LTREE_NUM_BITMASKS; j++) {
            ltree_bitmasks[i][j].resize(2 * HASH_OUTPUT_SIZE_BYTES, 0);
        }
    }
    
    // Initialize layer signatures
    layer_signatures.resize(d - 1);
}

// ============================================================================
// MultiLayerXMSSPublicKey Constructor
// ============================================================================

MultiLayerXMSSPublicKey::MultiLayerXMSSPublicKey(size_t num_layers,
                                                 size_t layer_height)
    : d(num_layers), h_prime(layer_height) {
    
    root.resize(HASH_OUTPUT_SIZE_BYTES, 0);
    
    // Initialize bitmasks for XMSS trees
    xmss_bitmasks.resize(d);
    for (size_t i = 0; i < d; i++) {
        xmss_bitmasks[i].resize(h_prime);
        for (size_t j = 0; j < h_prime; j++) {
            xmss_bitmasks[i][j].resize(2 * HASH_OUTPUT_SIZE_BYTES, 0);
        }
    }
    
    // Initialize bitmasks for L-Tree
    ltree_bitmasks.resize(d);
    for (size_t i = 0; i < d; i++) {
        ltree_bitmasks[i].resize(LTREE_NUM_BITMASKS);
        for (size_t j = 0; j < LTREE_NUM_BITMASKS; j++) {
            ltree_bitmasks[i][j].resize(2 * HASH_OUTPUT_SIZE_BYTES, 0);
        }
    }
}

// ============================================================================
// MultiLayerXMSSProof Constructor and Methods
// ============================================================================

MultiLayerXMSSProof::MultiLayerXMSSProof(size_t num_layers,
                                         size_t layer_height)
    : d(num_layers) {
    
    wots_sigs.resize(d);
    auth_paths.resize(d);
    
    for (size_t i = 0; i < d; i++) {
        auth_paths[i].resize(layer_height);
        for (size_t j = 0; j < layer_height; j++) {
            auth_paths[i][j].resize(HASH_OUTPUT_SIZE_BYTES, 0);
        }
    }
}

std::vector<uint8_t> MultiLayerXMSSProof::Serialize() const {
    std::vector<uint8_t> result;
    
    // Serialize number of layers
    result.push_back(static_cast<uint8_t>(d));
    
    // Serialize each layer's signature and path
    for (size_t i = 0; i < d; i++) {
        // Serialize WOTS+ signature
        for (const auto& component : wots_sigs[i].sig_components) {
            result.insert(result.end(), component.begin(), component.end());
        }
        
        // Serialize authentication path
        for (const auto& node : auth_paths[i]) {
            result.insert(result.end(), node.begin(), node.end());
        }
    }
    
    return result;
}

MultiLayerXMSSProof MultiLayerXMSSProof::Deserialize(
    const std::vector<uint8_t>& data) {
    if (data.empty()) {
        throw std::runtime_error("Cannot deserialize empty proof");
    }
    
    size_t pos = 0;
    size_t num_layers = data[pos++];
    size_t layer_height = DEFAULT_LAYER_HEIGHT;
    
    MultiLayerXMSSProof proof(num_layers, layer_height);
    
    for (size_t i = 0; i < num_layers; i++) {
        // Deserialize WOTS+ signature
        proof.wots_sigs[i].sig_components.resize(WOTS_L);
        for (size_t j = 0; j < WOTS_L; j++) {
            if (pos + HASH_OUTPUT_SIZE_BYTES > data.size()) {
                throw std::runtime_error("Truncated proof data");
            }
            proof.wots_sigs[i].sig_components[j].assign(
                data.begin() + pos,
                data.begin() + pos + HASH_OUTPUT_SIZE_BYTES);
            pos += HASH_OUTPUT_SIZE_BYTES;
        }
        
        // Deserialize authentication path
        for (size_t j = 0; j < layer_height; j++) {
            if (pos + HASH_OUTPUT_SIZE_BYTES > data.size()) {
                throw std::runtime_error("Truncated proof data");
            }
            proof.auth_paths[i][j].assign(
                data.begin() + pos,
                data.begin() + pos + HASH_OUTPUT_SIZE_BYTES);
            pos += HASH_OUTPUT_SIZE_BYTES;
        }
    }
    
    return proof;
}

// ============================================================================
// MULTI-LAYER XMSS KEY GENERATION
// ============================================================================

std::pair<MultiLayerXMSSSecretKey, MultiLayerXMSSPublicKey>
MultiXMSS_KeyGen(size_t num_layers, size_t layer_height) {
    
    MultiLayerXMSSSecretKey sk(num_layers, layer_height);
    MultiLayerXMSSPublicKey pk(num_layers, layer_height);
    
    // MODIFIED: KeyGen for 2-layer design
    // - Layer 0 (bottom): 16 leaves, signs input, regenerated after 16 evals
    // - Layer 1 (top): 16 leaves, signs layer 0 root, loops back after 16 evals
    
    // Copy bitmasks to both keys
    sk.xmss_bitmasks = pk.xmss_bitmasks;
    sk.ltree_bitmasks = pk.ltree_bitmasks;
    
    // Generate random seeds for each layer (both current and next)
    PRGState prg(std::vector<uint8_t>(HASH_OUTPUT_SIZE_BYTES, 0x42));
    
    for (size_t i = 0; i < num_layers; i++) {
        // Generate seed for current tree
        sk.Scur[i] = PRG_generate(prg);
        
        // Generate seed for next tree
        // MODIFIED: For layer 1 (top), this next tree will never be used since
        // we loop back to leaf 0 after exhausting all 16 leaves
        sk.Snext[i] = PRG_generate(prg);
    }
    
    // Generate bitmasks for all layers
    for (size_t layer = 0; layer < num_layers; layer++) {
        // XMSS tree bitmasks (each needs 2*HASH_OUTPUT_SIZE_BYTES)
        for (size_t level = 0; level < layer_height; level++) {
            std::vector<uint8_t> bitmask_part1 = PRG_generate(prg);
            std::vector<uint8_t> bitmask_part2 = PRG_generate(prg);
            bitmask_part1.insert(bitmask_part1.end(),
                                bitmask_part2.begin(),
                                bitmask_part2.end());
            sk.xmss_bitmasks[layer][level] = bitmask_part1;
            pk.xmss_bitmasks[layer][level] = bitmask_part1;
        }
        
        // L-Tree bitmasks (each needs 2*HASH_OUTPUT_SIZE_BYTES)
        for (size_t j = 0; j < LTREE_NUM_BITMASKS; j++) {
            std::vector<uint8_t> bitmask_part1 = PRG_generate(prg);
            std::vector<uint8_t> bitmask_part2 = PRG_generate(prg);
            bitmask_part1.insert(bitmask_part1.end(),
                                bitmask_part2.begin(),
                                bitmask_part2.end());
            sk.ltree_bitmasks[layer][j] = bitmask_part1;
            pk.ltree_bitmasks[layer][j] = bitmask_part1;
        }
    }
    
    // Build XMSS trees for each layer and collect roots
    std::vector<std::vector<uint8_t>> layer_roots(num_layers);
    
    for (size_t layer = 0; layer < num_layers; layer++) {
        // MODIFIED: Build 2 XMSS trees
        // Layer 0: Will be regenerated every 16 evaluations
        // Layer 1: Static tree that never changes (we loop within it)
        
        // Generate XMSS tree for current layer using TreeHash algorithm
        XMSSTree tree(layer_height, sk.xmss_bitmasks[layer]);
        
        // MODIFIED COMMENT: Each layer has 2^4 = 16 leaves
        // Generate all 2^h_prime WOTS+ key pairs and process them
        PRGState layer_prg(sk.Scur[layer]);
        
        for (size_t leaf_idx = 0; leaf_idx < (1UL << layer_height); leaf_idx++) {
            // Generate WOTS+ key pair from seed
            std::vector<uint8_t> key_seed = PRG_generate(layer_prg);
            
            auto [wots_sk, wots_pk] = WOTS_KeyGen(key_seed);
            
            // Apply L-Tree to get leaf
            std::vector<std::vector<uint8_t>> wots_pk_components =
                wots_pk.pk_components;
            
            std::vector<uint8_t> leaf = LTree(wots_pk_components,
                                              sk.ltree_bitmasks[layer]);
            
            // Add to tree using TreeHash
            XMSSTreeNode node(leaf, 0);
            tree.TreeHash(node);
        }
        
        // Get root
        layer_roots[layer] = tree.GetRoot();
    }
    
    // Create WOTS+ signatures connecting layers
    // σ_1 (layer_signatures[0]) signs the root of layer 0 using a key from layer 1
    
    // MODIFIED: With 2 layers, we only have 1 layer signature
    // layer_signatures[0] = signature from layer 1 key 0 signing layer 0 root
    // layer_signatures[1] doesn't exist (only 1 element in the d-1 sized array)
    
    for (size_t i = 1; i < num_layers; i++) {
        // Get WOTS+ key from layer i at index 0
        // MODIFIED COMMENT: For layer 1 (i=1), use the WOTS+ key at index 0
        // This key will sign the root of layer 0
        PRGState layer_prg(sk.Scur[i]);
        std::vector<uint8_t> key_seed = PRG_generate(layer_prg);
        
        auto [wots_sk, _] = WOTS_KeyGen(key_seed);
        
        // Sign the root of layer i-1
        // MODIFIED: layer_signatures[0] = signature of layer_0_root by layer_1_key_0
        sk.layer_signatures[i - 1] = WOTS_Sign(wots_sk, layer_roots[i - 1]);
    }
    
    // The public key root is the root of the top layer
    // MODIFIED: pk.root = root of layer 1 (the top/only changing layer from verifier perspective)
    pk.root = layer_roots[num_layers - 1];
    
    return {sk, pk};
}

// ============================================================================
// HELPER: COMPUTE AUTHENTICATION PATH FOR A LAYER
// ============================================================================

/**
 * FIXED: Properly compute authentication path for a leaf in a given layer
 * 
 * This function computes the authentication path by finding sibling nodes
 * at each level up the tree, similar to XMSS_Sign.
 * 
 * @param seed               Master seed for this layer
 * @param ltree_bitmasks     L-Tree bitmasks
 * @param xmss_bitmasks      XMSS tree bitmasks
 * @param layer_height       Height of the layer tree (h')
 * @param leaf_index         Which leaf to compute path for
 * @return                   Authentication path (h' nodes)
 */
static std::vector<std::vector<uint8_t>> compute_layer_auth_path(
    const std::vector<uint8_t>& seed,
    const std::vector<std::vector<uint8_t>>& ltree_bitmasks,
    const std::vector<std::vector<uint8_t>>& xmss_bitmasks,
    size_t layer_height,
    size_t leaf_index) {
    
    std::vector<std::vector<uint8_t>> auth_path;
    
    // For each level in the tree
    for (size_t level = 0; level < layer_height; ++level) {
        // Find the sibling index at this level
        size_t sibling_index = leaf_index ^ (1UL << level);
        
        // Compute the sibling node at this level
        // The sibling is built from the leaves that contribute to it
        size_t leaves_per_node = 1UL << level;
        size_t start_leaf = sibling_index * leaves_per_node;
        size_t end_leaf = start_leaf + leaves_per_node;
        
        // Create subtree with appropriate bitmasks
        std::vector<std::vector<uint8_t>> subtree_bitmasks(
            xmss_bitmasks.begin(),
            xmss_bitmasks.begin() + level);
        
        XMSSTree subtree(level, subtree_bitmasks);
        
        // Build the sibling subtree from leaves
        PRGState layer_prg(seed);
        
        for (size_t leaf_idx = 0; leaf_idx < end_leaf; ++leaf_idx) {
            if (leaf_idx < start_leaf) {
                // Skip leaves before the sibling range
                PRG_generate(layer_prg);
            } else {
                // Generate this sibling's leaves
                std::vector<uint8_t> key_seed = PRG_generate(layer_prg);
                auto [wots_sk, wots_pk] = WOTS_KeyGen(key_seed);
                std::vector<uint8_t> leaf_value = LTree(wots_pk.pk_components, ltree_bitmasks);
                
                XMSSTreeNode leaf_node(leaf_value, 0);
                subtree.TreeHash(leaf_node);
            }
        }
        
        // Get the root of the sibling subtree
        auth_path.push_back(subtree.GetRoot());
    }
    
    return auth_path;
}

// ============================================================================
// MULTI-LAYER XMSS EVALUATION
// ============================================================================

MultiLayerXMSSProof MultiXMSS_Eval(MultiLayerXMSSSecretKey& sk,
                                    const std::vector<uint8_t>& message) {
    
    MultiLayerXMSSProof proof(sk.d, sk.h_prime);
    
    // MODIFIED: 2-layer design with looping top layer
    // Each layer has 2^4 = 16 leaves
    
    // Compute counter positions for each layer
    // Layer 0 (bottom): cycles through 0-15, then resets and gets new tree
    uint64_t layer0_pos = sk.counter % (1UL << sk.h_prime);
    
    // Layer 1 (top): cycles through 0-15 indefinitely (wraps around, never changes)
    // When layer 0 goes from 15 to 0, layer 1 increments to sign the new layer 0 tree
    uint64_t layer1_pos = sk.top_layer_index % (1UL << sk.h_prime);
    
    // Current message to sign (starts with actual input)
    std::vector<uint8_t> current_msg = message;
    
    // ========================================================================
    // LAYER 0 (BOTTOM): Sign the input message
    // ========================================================================
    
    // MODIFIED COMMENT: Layer 0 uses layer0_pos to select which leaf signs
    // Generate WOTS+ key pair at position layer0_pos in layer 0
    PRGState layer0_prg(sk.Scur[0]);
    
    // Skip to the right WOTS+ key
    for (uint64_t j = 0; j <= layer0_pos; j++) {
        if (j < layer0_pos) {
            PRG_generate(layer0_prg);
        }
    }
    
    std::vector<uint8_t> key_seed = PRG_generate(layer0_prg);
    auto [wots_sk0, wots_pk0] = WOTS_KeyGen(key_seed);
    
    // Sign the input message with WOTS+ key at layer0_pos
    proof.wots_sigs[0] = WOTS_Sign(wots_sk0, current_msg);
    
    // Compute authentication path for layer 0
    // FIXED: Properly compute authentication path using helper function
    proof.auth_paths[0] = compute_layer_auth_path(
        sk.Scur[0],
        sk.ltree_bitmasks[0],
        sk.xmss_bitmasks[0],
        sk.h_prime,
        layer0_pos
    );
    
    // Get the L-Tree output from layer 0 public key to pass to layer 1
    std::vector<std::vector<uint8_t>> pk_components0 = wots_pk0.pk_components;
    current_msg = LTree(pk_components0, sk.ltree_bitmasks[0]);
    
    // Also build tree for layer 0 to get root
    XMSSTree tree0(sk.h_prime, sk.xmss_bitmasks[0]);
    PRGState temp_prg(sk.Scur[0]);
    for (size_t leaf_idx = 0; leaf_idx < (1UL << sk.h_prime); leaf_idx++) {
        std::vector<uint8_t> temp_seed = PRG_generate(temp_prg);
        auto [temp_wots_sk, temp_wots_pk] = WOTS_KeyGen(temp_seed);
        std::vector<uint8_t> leaf_value = LTree(temp_wots_pk.pk_components, sk.ltree_bitmasks[0]);
        XMSSTreeNode leaf_node(leaf_value, 0);
        tree0.TreeHash(leaf_node);
    }
    
    // ========================================================================
    // LAYER 1 (TOP): Sign the layer 0 root using WRAPPING index
    // ========================================================================
    
    // MODIFIED COMMENT: Layer 1 uses layer1_pos which wraps back instead of 
    // getting a new tree. When this reaches 16, it goes back to 0.
    
    // Generate WOTS+ key pair at position layer1_pos in layer 1
    PRGState layer1_prg(sk.Scur[1]);
    
    // Skip to the right WOTS+ key
    for (uint64_t j = 0; j <= layer1_pos; j++) {
        if (j < layer1_pos) {
            PRG_generate(layer1_prg);
        }
    }
    
    std::vector<uint8_t> key_seed1 = PRG_generate(layer1_prg);
    auto [wots_sk1, wots_pk1] = WOTS_KeyGen(key_seed1);
    
    // Sign the layer 0 root with WOTS+ key at layer1_pos
    proof.wots_sigs[1] = WOTS_Sign(wots_sk1, current_msg);
    
    // Compute authentication path for layer 1
    // FIXED: Properly compute authentication path using helper function
    proof.auth_paths[1] = compute_layer_auth_path(
        sk.Scur[1],
        sk.ltree_bitmasks[1],
        sk.xmss_bitmasks[1],
        sk.h_prime,
        layer1_pos
    );
    
    // ========================================================================
    // COUNTER AND STATE UPDATE
    // ========================================================================
    
    // Update counter
    sk.counter++;
    
    // MODIFIED: Counter logic for 2-layer design
    // When bottom layer (layer 0) is exhausted (counter % 16 == 0):
    // 1. Swap current and next seeds for layer 0 only (bottom layer)
    // 2. Increment top_layer_index for layer 1
    // 3. Generate new next seeds for layer 0
    // 4. Top layer (layer 1) NEVER changes - it just loops back
    
    if (sk.counter % (1UL << sk.h_prime) == 0) {
        // Bottom layer swap and regeneration
        sk.Scur[0] = sk.Snext[0];
        
        // Generate new next seed for layer 0
        PRGState prg(std::vector<uint8_t>(HASH_OUTPUT_SIZE_BYTES, 0x42));
        sk.Snext[0] = PRG_generate(prg);
        
        // MODIFIED: Increment top_layer_index (layer 1 index)
        // This moves to the next leaf in the top layer tree
        sk.top_layer_index++;
        
        // MODIFIED COMMENT: Note - top_layer_index will wrap around when it reaches 16
        // The modulo operation in layer1_pos handles the wrapping
    }
    
    return proof;
}

// ============================================================================
// MULTI-LAYER XMSS VERIFICATION
// ============================================================================

bool MultiXMSS_Verify(const MultiLayerXMSSPublicKey& pk,
                      const std::vector<uint8_t>& /* message */,
                      const MultiLayerXMSSProof& proof) {
    
    if (proof.d != pk.d) {
        return false;
    }
    
    if (proof.wots_sigs.size() != pk.d || proof.auth_paths.size() != pk.d) {
        return false;
    }
    
    // For simplified verification, we just check the proof structure
    // Full verification would reconstruct the root from the signature chains
    
    // Check that all auth paths have the correct size
    for (size_t layer = 0; layer < pk.d; layer++) {
        if (proof.auth_paths[layer].size() != pk.h_prime) {
            return false;
        }
        
        // Check that all nodes in the auth path are the correct size
        for (size_t level = 0; level < pk.h_prime; level++) {
            if (proof.auth_paths[layer][level].size() != HASH_OUTPUT_SIZE_BYTES) {
                return false;
            }
        }
    }
    
    // Check that all WOTS signatures have the correct number of components
    for (size_t layer = 0; layer < pk.d; layer++) {
        if (proof.wots_sigs[layer].sig_components.size() != WOTS_L) {
            return false;
        }
        
        // Check that all signature components are the correct size
        for (size_t i = 0; i < WOTS_L; i++) {
            if (proof.wots_sigs[layer].sig_components[i].size() != HASH_OUTPUT_SIZE_BYTES) {
                return false;
            }
        }
    }
    
    // In a complete implementation, we would:
    // 1. For each layer, reconstruct the WOTS+ public key from signature
    // 2. Apply L-Tree to get the leaf
    // 3. Use the auth path to recompute the root
    // 4. Check that the final root matches pk.root
    //
    // For now, we just verify the structure is correct
    
    return true;
}

// ============================================================================
// MULTI-LAYER XMSS EVALUATION WITH SPECIFIC INDICES
// ============================================================================

MultiLayerXMSSProof MultiXMSS_EvalWithIndices(MultiLayerXMSSSecretKey& sk,
                                               const std::vector<size_t>& layer_indices) {
    
    if (layer_indices.size() != sk.d) {
        throw std::invalid_argument("MultiXMSS_EvalWithIndices: indices size must match number of layers");
    }
    
    // Check that all indices are within bounds
    for (size_t i = 0; i < sk.d; i++) {
        if (layer_indices[i] >= (1UL << sk.h_prime)) {
            throw std::invalid_argument("MultiXMSS_EvalWithIndices: index " + 
                                       std::to_string(i) + " out of bounds");
        }
    }
    
    MultiLayerXMSSProof proof(sk.d, sk.h_prime);
    
    // Current message to sign
    std::vector<uint8_t> current_msg(HASH_OUTPUT_SIZE_BYTES, 0);
    
    // Process each layer from bottom to top
    for (size_t layer = 0; layer < sk.d; layer++) {
        size_t leaf_index = layer_indices[layer];
        
        // Generate WOTS+ key pair at position leaf_index in this layer
        PRGState layer_prg(sk.Scur[layer]);
        
        // Skip to the right WOTS+ key
        for (size_t j = 0; j < leaf_index; j++) {
            PRG_generate(layer_prg);
        }
        
        std::vector<uint8_t> key_seed = PRG_generate(layer_prg);
        auto [wots_sk, wots_pk] = WOTS_KeyGen(key_seed);
        
        // Sign the current message (input at layer 0, L-Tree output at layer > 0)
        proof.wots_sigs[layer] = WOTS_Sign(wots_sk, current_msg);
        
        // Compute authentication path for this layer
        proof.auth_paths[layer] = compute_layer_auth_path(
            sk.Scur[layer],
            sk.ltree_bitmasks[layer],
            sk.xmss_bitmasks[layer],
            sk.h_prime,
            leaf_index
        );
        
        // Get the L-Tree output from this layer's public key to pass to next layer
        std::vector<std::vector<uint8_t>> pk_components = wots_pk.pk_components;
        current_msg = LTree(pk_components, sk.ltree_bitmasks[layer]);
    }
    
    return proof;
}

static std::vector<uint8_t> reconstruct_xmss_root(
    const std::vector<uint8_t>& leaf,
    const std::vector<std::vector<uint8_t>>& auth_path,
    const std::vector<std::vector<uint8_t>>& xmss_bitmasks,
    size_t leaf_index,
    size_t tree_height) {
    
    std::vector<uint8_t> current = leaf;
    
    // Traverse authentication path from leaf to root
    for (size_t level = 0; level < tree_height; level++) {
        bool is_left = ((leaf_index >> level) & 1) == 0;
        
        if (is_left) {
            // Current is left child, auth_path[level] is right
            std::vector<uint8_t> left = current;
            std::vector<uint8_t> right = auth_path[level];
            
            // Apply bitmask and hash: H(left, right) with bitmask applied
            std::vector<uint8_t> left_masked = left;
            std::vector<uint8_t> right_masked = right;
            
            for (size_t i = 0; i < HASH_OUTPUT_SIZE_BYTES; i++) {
                left_masked[i] ^= xmss_bitmasks[level][i];
                right_masked[i] ^= xmss_bitmasks[level][HASH_OUTPUT_SIZE_BYTES + i];
            }
            
            current = H(left_masked, right_masked);
        } else {
            // Current is right child, auth_path[level] is left
            std::vector<uint8_t> left = auth_path[level];
            std::vector<uint8_t> right = current;
            
            // Apply bitmask and hash: H(left, right) with bitmask applied
            std::vector<uint8_t> left_masked = left;
            std::vector<uint8_t> right_masked = right;
            
            for (size_t i = 0; i < HASH_OUTPUT_SIZE_BYTES; i++) {
                left_masked[i] ^= xmss_bitmasks[level][i];
                right_masked[i] ^= xmss_bitmasks[level][HASH_OUTPUT_SIZE_BYTES + i];
            }
            
            current = H(left_masked, right_masked);
        }
    }
    
    return current;
}

// Verify multi-layer XMSS proof using root, signatures, authentication paths, and leaf indices
bool MultiXMSS_VerifyComplete(const MultiLayerXMSSPublicKey& pk,
                               const MultiLayerXMSSProof& proof,
                               const std::vector<uint8_t>& message,
                               const std::vector<size_t>& layer_indices) {
    try {
        // Validate basic structure
        if (proof.wots_sigs.size() != pk.d || proof.auth_paths.size() != pk.d) {
            std::cerr << "DEBUG: proof size mismatch" << std::endl;
            return false;
        }
        
        if (layer_indices.size() != pk.d) {
            std::cerr << "DEBUG: layer_indices size mismatch" << std::endl;
            return false;
        }
        
        if (message.size() != HASH_OUTPUT_SIZE_BYTES) {
            std::cerr << "DEBUG: message size mismatch" << std::endl;
            return false;
        }
        
        // Current message to verify
        std::vector<uint8_t> current_msg = message;
        
        // Process each layer from bottom to top
        for (size_t layer = 0; layer < pk.d; layer++) {
            std::cerr << "\n=== LAYER " << layer << " VERIFICATION ===" << std::endl;
            
            // Validate authentication path structure
            if (proof.auth_paths[layer].size() != pk.h_prime) {
                std::cerr << "DEBUG: auth path size mismatch for layer " << layer << std::endl;
                return false;
            }
            
            for (size_t i = 0; i < proof.auth_paths[layer].size(); i++) {
                if (proof.auth_paths[layer][i].size() != HASH_OUTPUT_SIZE_BYTES) {
                    std::cerr << "DEBUG: auth path node size mismatch" << std::endl;
                    return false;
                }
            }
            
            // Validate WOTS+ signature structure
            if (proof.wots_sigs[layer].sig_components.size() != WOTS_L) {
                std::cerr << "DEBUG: WOTS sig size mismatch" << std::endl;
                return false;
            }
            
            for (size_t i = 0; i < WOTS_L; i++) {
                if (proof.wots_sigs[layer].sig_components[i].size() != HASH_OUTPUT_SIZE_BYTES) {
                    std::cerr << "DEBUG: WOTS sig component size mismatch" << std::endl;
                    return false;
                }
            }
            
            std::cerr << "Input message: ";
            for (size_t i = 0; i < 16 && i < current_msg.size(); i++) {
                std::cerr << std::hex << (int)current_msg[i];
            }
            std::cerr << "..." << std::endl;
            
            // Reconstruct WOTS+ public key from signature and message
            WOTSPublicKey wots_pk = LTree_ReconstructPublicKeyFromSignatureStruct(
                proof.wots_sigs[layer], 
                current_msg
            );
            
            std::cerr << "WOTS+ components reconstructed: " << wots_pk.pk_components.size() << " (expect " << WOTS_L << ")" << std::endl;
            
            // Compute L-Tree root (the leaf for XMSS tree)
            std::vector<uint8_t> leaf = LTree(wots_pk.pk_components, pk.ltree_bitmasks[layer]);
            
            std::cerr << "L-Tree root (XMSS leaf): ";
            for (size_t i = 0; i < 16 && i < leaf.size(); i++) {
                std::cerr << std::hex << (int)leaf[i];
            }
            std::cerr << "..." << std::endl;
            
            // Reconstruct XMSS root from leaf and authentication path
            std::cerr << "Leaf index for layer " << layer << ": " << layer_indices[layer] << std::endl;
            std::vector<uint8_t> reconstructed_root = reconstruct_xmss_root(
                leaf,
                proof.auth_paths[layer],
                pk.xmss_bitmasks[layer],
                layer_indices[layer],
                pk.h_prime
            );
            
            std::cerr << "Reconstructed root: ";
            for (size_t i = 0; i < 16 && i < reconstructed_root.size(); i++) {
                std::cerr << std::hex << (int)reconstructed_root[i];
            }
            std::cerr << "..." << std::endl;
            
            // For next layer (if exists), this root becomes the message
            current_msg = reconstructed_root;
        }
        
        std::cerr << "\nFinal reconstructed root: ";
        for (size_t i = 0; i < 16 && i < current_msg.size(); i++) {
            std::cerr << std::hex << (int)current_msg[i];
        }
        std::cerr << "..." << std::endl;
        
        std::cerr << "Expected root (pk.root): ";
        for (size_t i = 0; i < 16 && i < pk.root.size(); i++) {
            std::cerr << std::hex << (int)pk.root[i];
        }
        std::cerr << "..." << std::endl;
        
        // Final reconstructed root should match the public key root
        bool result = current_msg == pk.root;
        std::cerr << "Verification result: " << (result ? "VALID" : "INVALID") << std::endl;
        return result;
        
    } catch (const std::exception& e) {
        std::cerr << "DEBUG: Exception during verification: " << e.what() << std::endl;
        return false;
    } catch (...) {
        std::cerr << "DEBUG: Unknown exception during verification" << std::endl;
        return false;
    }
}

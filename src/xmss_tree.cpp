// XMSS tree implementation with TreeHash algorithm

#include "xmss_tree.h"
#include <stdexcept>
#include <algorithm>
#include <cstring>

// XOR two byte vectors
static std::vector<uint8_t> XOR_vectors(const std::vector<uint8_t>& a,
                                        const std::vector<uint8_t>& b) {
    if (a.size() != b.size()) {
        throw std::invalid_argument("XOR_vectors: sizes must match");
    }
    std::vector<uint8_t> result(a.size());
    for (size_t i = 0; i < a.size(); ++i) {
        result[i] = a[i] ^ b[i];
    }
    return result;
}

// Concatenate two byte vectors
static std::vector<uint8_t> concatenate(const std::vector<uint8_t>& left,
                                        const std::vector<uint8_t>& right) {
    std::vector<uint8_t> result;
    result.reserve(left.size() + right.size());
    result.insert(result.end(), left.begin(), left.end());
    result.insert(result.end(), right.begin(), right.end());
    return result;
}

// Generate WOTS+ key pair at given index from seed
static std::pair<WOTSSecretKey, WOTSPublicKey> 
generate_WOTS_keypair_at_index(const std::vector<uint8_t>& master_seed, 
                               size_t index) {
    PRGState prg(master_seed);
    
    for (size_t i = 0; i < index; ++i) {
        PRG_generate(prg);
    }
    
    std::vector<uint8_t> key_seed = PRG_generate(prg);
    auto [sk, pk] = WOTS_KeyGen(key_seed);
    
    return {sk, pk};
}

// Initialize XMSSTree with bitmasks
XMSSTree::XMSSTree(size_t h, const std::vector<std::vector<uint8_t>>& tree_bitmasks)
    : bitmasks(tree_bitmasks) {
    if (bitmasks.size() != h) {
        throw std::invalid_argument("XMSSTree: bitmask count must match height");
    }
}

// Add leaf to tree using TreeHash algorithm
void XMSSTree::TreeHash(const XMSSTreeNode& leaf) {
    XMSSTreeNode current = leaf;
    
    while (!nodeStack.empty() && nodeStack.top().height == current.height) {
        XMSSTreeNode top = nodeStack.top();
        nodeStack.pop();
        
        size_t newHeight = current.height + 1;
        
        if (newHeight - 1 >= bitmasks.size()) {
            throw std::logic_error("XMSSTree::TreeHash: exceeded tree height");
        }
        
        std::vector<uint8_t> concatenated = concatenate(top.value, current.value);
        std::vector<uint8_t> xored = XOR_vectors(concatenated, bitmasks[newHeight - 1]);
        
        std::vector<uint8_t> left_half(xored.begin(), xored.begin() + HASH_OUTPUT_SIZE_BYTES);
        std::vector<uint8_t> right_half(xored.begin() + HASH_OUTPUT_SIZE_BYTES, xored.end());
        std::vector<uint8_t> hashed = H(left_half, right_half);
        
        current = XMSSTreeNode(hashed, newHeight);
    }
    
    nodeStack.push(current);
}

// Get final tree root
std::vector<uint8_t> XMSSTree::GetRoot() {
    if (nodeStack.empty()) {
        throw std::logic_error("XMSSTree::GetRoot: stack is empty");
    }
    
    if (nodeStack.size() > 1) {
        throw std::logic_error("XMSSTree::GetRoot: stack has multiple nodes");
    }
    
    return nodeStack.top().value;
}

// Reset tree state
void XMSSTree::Reset() {
    while (!nodeStack.empty()) {
        nodeStack.pop();
    }
}

// Initialize XMSS parameters
void XMSS_Setup(size_t /* h */) {
    // Placeholder
}

// Generate XMSS key pair with random seed and bitmasks
std::pair<XMSSSecretKey, XMSSPublicKey> XMSS_KeyGen(size_t h) {
    PRGState prg_init(std::vector<uint8_t>(HASH_OUTPUT_SIZE_BYTES, 0));
    std::vector<uint8_t> master_seed = PRG_generate(prg_init);
    
    // Generate L-Tree bitmasks
    std::vector<std::vector<uint8_t>> ltree_bitmasks;
    for (int i = 0; i < LTREE_NUM_BITMASKS; ++i) {
        std::vector<uint8_t> bitmask;
        std::vector<uint8_t> part1 = PRG_generate(prg_init);
        std::vector<uint8_t> part2 = PRG_generate(prg_init);
        bitmask.insert(bitmask.end(), part1.begin(), part1.end());
        bitmask.insert(bitmask.end(), part2.begin(), part2.end());
        ltree_bitmasks.push_back(bitmask);
    }
    
    // Generate XMSS tree bitmasks
    std::vector<std::vector<uint8_t>> xmss_bitmasks;
    for (size_t i = 0; i < h; ++i) {
        std::vector<uint8_t> bitmask;
        std::vector<uint8_t> part1 = PRG_generate(prg_init);
        std::vector<uint8_t> part2 = PRG_generate(prg_init);
        bitmask.insert(bitmask.end(), part1.begin(), part1.end());
        bitmask.insert(bitmask.end(), part2.begin(), part2.end());
        xmss_bitmasks.push_back(bitmask);
    }
    
    XMSSSecretKey sk(h);
    sk.seed = master_seed;
    sk.ltree_bitmasks = ltree_bitmasks;
    sk.xmss_bitmasks = xmss_bitmasks;
    
    // Build tree using TreeHash
    XMSSTree tree(h, xmss_bitmasks);
    size_t num_leaves = 1UL << h;
    
    for (size_t i = 0; i < num_leaves; ++i) {
        auto [wots_sk, wots_pk] = generate_WOTS_keypair_at_index(master_seed, i);
        std::vector<uint8_t> leaf_value = LTree(wots_pk.pk_components, ltree_bitmasks);
        XMSSTreeNode leaf(leaf_value, 0);
        tree.TreeHash(leaf);
    }
    
    std::vector<uint8_t> root = tree.GetRoot();
    
    XMSSPublicKey pk;
    pk.root = root;
    pk.bitmasks = xmss_bitmasks;
    pk.ltree_bitmasks = ltree_bitmasks;
    
    return {sk, pk};
}

// Compute node at given level and index
static std::vector<uint8_t> compute_node_at_level(
    const std::vector<uint8_t>& master_seed,
    const std::vector<std::vector<uint8_t>>& ltree_bitmasks,
    const std::vector<std::vector<uint8_t>>& xmss_bitmasks,
    size_t level, size_t node_index, size_t /* tree_height */) {
    
    if (level == 0) {
        auto [wots_sk, wots_pk] = generate_WOTS_keypair_at_index(master_seed, node_index);
        return LTree(wots_pk.pk_components, ltree_bitmasks);
    }
    
    size_t leaves_per_node = 1UL << level;
    size_t start_leaf = node_index * leaves_per_node;
    size_t end_leaf = start_leaf + leaves_per_node;
    
    std::vector<std::vector<uint8_t>> subtree_bitmasks(
        xmss_bitmasks.begin(), 
        xmss_bitmasks.begin() + level);
    
    XMSSTree subtree(level, subtree_bitmasks);
    
    for (size_t leaf_idx = start_leaf; leaf_idx < end_leaf; ++leaf_idx) {
        auto [wots_sk, wots_pk] = generate_WOTS_keypair_at_index(master_seed, leaf_idx);
        std::vector<uint8_t> leaf_value = LTree(wots_pk.pk_components, ltree_bitmasks);
        XMSSTreeNode leaf_node(leaf_value, 0);
        subtree.TreeHash(leaf_node);
    }
    
    return subtree.GetRoot();
}

// Sign message at given index
XMSSSignature XMSS_Sign(const XMSSSecretKey& sk, size_t index,
                        const std::vector<uint8_t>& message) {
    size_t max_index = 1UL << sk.tree_height;
    if (index >= max_index) {
        throw std::invalid_argument("XMSS_Sign: index out of range");
    }
    
    if (message.size() != HASH_OUTPUT_SIZE_BYTES) {
        throw std::invalid_argument("XMSS_Sign: message must be 256 bits");
    }
    
    auto [wots_sk, wots_pk] = generate_WOTS_keypair_at_index(sk.seed, index);
    WOTSSignature wots_sig = WOTS_Sign(wots_sk, message);
    
    // Compute authentication path
    std::vector<std::vector<uint8_t>> auth_path;
    
    for (size_t level = 0; level < sk.tree_height; ++level) {
        size_t sibling_index = index ^ (1UL << level);
        std::vector<uint8_t> sibling = compute_node_at_level(
            sk.seed, sk.ltree_bitmasks, sk.xmss_bitmasks,
            level, sibling_index, sk.tree_height);
        
        auth_path.push_back(sibling);
    }
    
    XMSSSignature sig(sk.tree_height);
    sig.index = index;
    sig.wots_sig = wots_sig;
    sig.auth_path = auth_path;
    
    return sig;
}

// Verify XMSS signature
bool XMSS_Verify(const XMSSPublicKey& pk, const std::vector<uint8_t>& message,
                 const XMSSSignature& sig) {
    if (message.size() != HASH_OUTPUT_SIZE_BYTES) {
        return false;
    }
    
    size_t tree_height = sig.auth_path.size();
    
    if (sig.index >= (1UL << tree_height)) {
        return false;
    }
    
    // Reconstruct WOTS+ public key from signature
    auto msg_digits = BaseWEncode(message, WOTS_W, WOTS_L1);
    auto checksum_digits = ComputeChecksum(msg_digits, WOTS_W);
    
    std::vector<int> all_digits;
    all_digits.insert(all_digits.end(), msg_digits.begin(), msg_digits.end());
    all_digits.insert(all_digits.end(), checksum_digits.begin(), checksum_digits.end());
    
    WOTSPublicKey reconstructed_pk;
    for (int i = 0; i < WOTS_L; i++) {
        int digit = all_digits[i];
        if (digit < 0 || digit >= WOTS_W) {
            return false;
        }
        
        int remaining_chain = WOTS_W - 1 - digit;
        reconstructed_pk.pk_components[i] = ChainFunction(sig.wots_sig.sig_components[i], remaining_chain);
    }
    
    // Get leaf from L-Tree
    if (pk.ltree_bitmasks.size() != LTREE_NUM_BITMASKS) {
        return false;
    }
    
    std::vector<uint8_t> leaf = LTree(reconstructed_pk.pk_components, pk.ltree_bitmasks);
    
    // Traverse authentication path to recompute root
    std::vector<uint8_t> current = leaf;
    size_t index = sig.index;
    
    for (size_t level = 0; level < tree_height; ++level) {
        if (level >= sig.auth_path.size()) {
            return false;
        }
        
        std::vector<uint8_t> sibling = sig.auth_path[level];
        
        if (sibling.size() != HASH_OUTPUT_SIZE_BYTES) {
            return false;
        }
        
        bool current_is_left = ((index >> level) & 1) == 0;
        
        std::vector<uint8_t> concatenated;
        if (current_is_left) {
            concatenated = concatenate(current, sibling);
        } else {
            concatenated = concatenate(sibling, current);
        }
        
        if (level >= pk.bitmasks.size()) {
            return false;
        }
        
        std::vector<uint8_t> xored = XOR_vectors(concatenated, pk.bitmasks[level]);
        std::vector<uint8_t> left_half(xored.begin(), xored.begin() + HASH_OUTPUT_SIZE_BYTES);
        std::vector<uint8_t> right_half(xored.begin() + HASH_OUTPUT_SIZE_BYTES, xored.end());
        current = H(left_half, right_half);
    }
    
    return current == pk.root;
}

// Build XMSS tree and return root with authentication path for specific index
XMSSTreeOutput XMSS_BuildTree(const std::vector<uint8_t>& seed, 
                               size_t tree_height,
                               size_t leaf_index,
                               const std::vector<std::vector<uint8_t>>& xmss_bitmasks,
                               const std::vector<std::vector<uint8_t>>& ltree_bitmasks) {
    
    if (leaf_index >= (1UL << tree_height)) {
        throw std::invalid_argument("XMSS_BuildTree: leaf_index out of range");
    }
    
    XMSSTreeOutput output(tree_height);
    output.index = leaf_index;
    
    // Generate WOTS+ signature at the leaf index
    auto [wots_sk, wots_pk] = generate_WOTS_keypair_at_index(seed, leaf_index);
    
    // Compute the message to sign (just use a zero message for tree construction)
    std::vector<uint8_t> zero_msg(HASH_OUTPUT_SIZE_BYTES, 0);
    output.wots_sig = WOTS_Sign(wots_sk, zero_msg);
    
    // Build the tree using TreeHash and collect authentication path
    XMSSTree tree(tree_height, xmss_bitmasks);
    size_t num_leaves = 1UL << tree_height;
    
    // Track nodes at each level for authentication path computation
    std::vector<std::vector<std::vector<uint8_t>>> level_nodes(tree_height);
    
    for (size_t i = 0; i < num_leaves; ++i) {
        auto [sk_i, pk_i] = generate_WOTS_keypair_at_index(seed, i);
        std::vector<uint8_t> leaf_value = LTree(pk_i.pk_components, ltree_bitmasks);
        
        // Track the position of our target leaf
        if (i == leaf_index) {
            output.auth_path[0] = leaf_value;
        }
        
        XMSSTreeNode leaf(leaf_value, 0);
        tree.TreeHash(leaf);
    }
    
    // Get the root
    output.root = tree.GetRoot();
    
    // Now compute authentication path by rebuilding relevant subtrees
    for (size_t level = 0; level < tree_height; ++level) {
        size_t sibling_index = leaf_index ^ (1UL << level);
        
        // Compute the sibling node at this level
        std::vector<uint8_t> sibling = compute_node_at_level(
            seed, ltree_bitmasks, xmss_bitmasks,
            level, sibling_index, tree_height);
        
        if (level == 0) {
            // Leaf level
            auto [sk_sib, pk_sib] = generate_WOTS_keypair_at_index(seed, sibling_index);
            output.auth_path[level] = LTree(pk_sib.pk_components, ltree_bitmasks);
        } else {
            output.auth_path[level] = sibling;
        }
    }
    
    return output;
}

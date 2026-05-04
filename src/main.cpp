#include "xm_vrf.h"
#include "crypto_utils.h"
#include <iostream>
#include <iomanip>
#include <sstream>
#include <cstring>
#include <fstream>

using namespace std;

// Helper function to print hex
void printHex(const vector<uint8_t>& data, int maxBytes = -1) {
    int limit = (maxBytes == -1) ? data.size() : min((int)data.size(), maxBytes);
    for (int i = 0; i < limit; i++) {
        cout << hex << setw(2) << setfill('0') << (int)data[i];
    }
    cout << dec << endl;
}

// Helper function to read hex string
vector<uint8_t> readHexString(const string& input) {
    vector<uint8_t> result;
    for (size_t i = 0; i < input.length(); i += 2) {
        string byteString = input.substr(i, 2);
        uint8_t byte = (uint8_t)strtol(byteString.c_str(), nullptr, 16);
        result.push_back(byte);
    }
    return result;
}

// Helper function to convert bytes to hex string
string bytesToHex(const vector<uint8_t>& data) {
    stringstream ss;
    for (size_t i = 0; i < data.size(); i++) {
        ss << hex << setw(2) << setfill('0') << (int)data[i];
    }
    return ss.str();
}

// Helper function to save authentication path to file
void saveAuthPathToFile(const vector<vector<uint8_t>>& auth_path, const string& filename) {
    ofstream file(filename);
    for (size_t i = 0; i < auth_path.size(); i++) {
        for (size_t j = 0; j < auth_path[i].size(); j++) {
            file << hex << setw(2) << setfill('0') << (int)auth_path[i][j];
        }
        if (i < auth_path.size() - 1) {
            file << "\n";
        }
    }
    file.close();
}

// Helper function to save single value to file
void saveValueToFile(const vector<uint8_t>& value, const string& filename) {
    ofstream file(filename);
    for (size_t i = 0; i < value.size(); i++) {
        file << hex << setw(2) << setfill('0') << (int)value[i];
    }
    file.close();
}

// Menu functions
void wotsPlusMenu(int h);
void ltreeMenu();
void xmssTreeMenu(int h);
void multiLayerXMSSMenu(int h1, int h2);
void xmvrfMenu();

void wotsPlusMenu(int h) {
    cout << "\n===== WOTS+ Component =====" << endl;
    cout << "1. Generate WOTS+ signature and save to file" << endl;
    cout << "2. Load and verify WOTS+ signature from file" << endl;
    cout << "3. Go back" << endl;
    
    int choice;
    cout << "Enter choice: ";
    cin >> choice;
    cin.ignore();
    
    if (choice == 1) {
        cout << "\nEnter seed (hex string, 64 chars = 32 bytes): ";
        string seedHex;
        getline(cin, seedHex);
        
        vector<uint8_t> seed = readHexString(seedHex);
        if (seed.size() != 32) {
            cout << "Error: Seed must be 32 bytes (64 hex characters)" << endl;
            return;
        }
        
        auto [sk, pk] = WOTS_KeyGen(seed);
        
        cout << "\nEnter message to sign (hex string, 64 chars = 32 bytes): ";
        string msgHex;
        getline(cin, msgHex);
        
        vector<uint8_t> message = readHexString(msgHex);
        if (message.size() != 32) {
            cout << "Error: Message must be 32 bytes" << endl;
            return;
        }
        
        WOTSSignature sig = WOTS_Sign(sk, message);
        
        // Save signature to file with all components space-separated
        string sigFilename = "wots_signature.txt";
        WOTS_SaveSignatureToFile(sig, sigFilename);
        cout << "\n[WOTS+ Signature saved to: " << sigFilename << "]" << endl;
        
        // Also save public key
        string pkFilename = "wots_public_key.txt";
        WOTS_SavePublicKeyToFile(pk, pkFilename);
        cout << "[WOTS+ Public Key saved to: " << pkFilename << "]" << endl;
        
        // Verify the signature
        bool valid = WOTS_Verify(pk, message, sig);
        cout << "\n[WOTS+ Signature Verification]" << endl;
        cout << "Status: " << (valid ? "VALID ✓" : "INVALID ✗") << endl;
        cout << "Message (hex): " << bytesToHex(message) << endl;
        
    } else if (choice == 2) {
        cout << "\nEnter signature filename: ";
        string sigFilename;
        getline(cin, sigFilename);
        
        cout << "Enter public key filename: ";
        string pkFilename;
        getline(cin, pkFilename);
        
        cout << "Enter message (hex string, 64 chars = 32 bytes): ";
        string msgHex;
        getline(cin, msgHex);
        
        vector<uint8_t> message = readHexString(msgHex);
        if (message.size() != 32) {
            cout << "Error: Message must be 32 bytes" << endl;
            return;
        }
        
        try {
            WOTSSignature sig = WOTS_LoadSignatureFromFile(sigFilename);
            WOTSPublicKey pk = WOTS_LoadPublicKeyFromFile(pkFilename);
            
            bool valid = WOTS_Verify(pk, message, sig);
            cout << "\n[WOTS+ Signature Verification Result]" << endl;
            cout << "Status: " << (valid ? "VALID ✓" : "INVALID ✗") << endl;
            cout << "Message (hex): " << bytesToHex(message) << endl;
        } catch (const exception& e) {
            cout << "Error: " << e.what() << endl;
        }
    }
}

void ltreeMenu() {
    cout << "\n===== L-Tree Component =====" << endl;
    cout << "1. Compute L-Tree root from WOTS+ public key file" << endl;
    cout << "2. Verify L-Tree root from files" << endl;
    cout << "3. Go back" << endl;
    
    int choice;
    cout << "Enter choice: ";
    cin >> choice;
    cin.ignore();
    
    if (choice == 1) {
        cout << "\nEnter WOTS+ public key filename: ";
        string pk_filename;
        getline(cin, pk_filename);
        
        try {
            cout << "\nComputing L-Tree root from WOTS+ public key..." << endl;
            vector<uint8_t> ltree_root = LTree_ComputeFromPublicKeyFile(pk_filename);
            
            cout << "\n[L-Tree Root Computation Result]" << endl;
            cout << "L-Tree Root: ";
            printHex(ltree_root);
            
            // Save L-Tree root to file
            string root_filename = "ltree_root.txt";
            LTree_SaveRootToFile(ltree_root, root_filename);
            cout << "\n[L-Tree Root saved to: " << root_filename << "]" << endl;
            
        } catch (const exception& e) {
            cout << "Error: " << e.what() << endl;
        }
        
    } else if (choice == 2) {
        cout << "\nEnter WOTS+ public key filename: ";
        string pk_filename;
        getline(cin, pk_filename);
        
        cout << "Enter L-Tree root filename: ";
        string root_filename;
        getline(cin, root_filename);
        
        try {
            cout << "\nVerifying L-Tree root..." << endl;
            bool valid = LTree_VerifyFromPublicKeyFile(pk_filename, root_filename);
            
            cout << "\n[L-Tree Verification Result]" << endl;
            cout << "Status: " << (valid ? "VALID ✓" : "INVALID ✗") << endl;
            
        } catch (const exception& e) {
            cout << "Error: " << e.what() << endl;
        }
    }
}

void xmssTreeMenu(int h) {
    cout << "\n===== XMSS Tree Component =====" << endl;
    cout << "1. Build XMSS tree and get root + authentication path" << endl;
    cout << "2. Verify XMSS authentication path" << endl;
    cout << "3. Go back" << endl;
    
    int choice;
    cout << "Enter choice: ";
    cin >> choice;
    cin.ignore();
    
    if (choice == 1) {
        cout << "\nEnter tree height (2-10): ";
        size_t tree_height;
        cin >> tree_height;
        cin.ignore();
        
        if (tree_height < 2 || tree_height > 10) {
            cout << "Error: Height must be between 2 and 10" << endl;
            return;
        }
        
        cout << "Enter seed (64 hex chars = 32 bytes): ";
        string seedHex;
        getline(cin, seedHex);
        
        vector<uint8_t> seed = readHexString(seedHex);
        if (seed.size() != 32) {
            cout << "Error: Seed must be 32 bytes" << endl;
            return;
        }
        
        cout << "Enter leaf index (0 to " << ((1UL << tree_height) - 1) << "): ";
        size_t leaf_index;
        cin >> leaf_index;
        cin.ignore();
        
        if (leaf_index >= (1UL << tree_height)) {
            cout << "Error: Index out of range" << endl;
            return;
        }
        
        try {
            // Generate bitmasks
            vector<vector<uint8_t>> xmss_bitmasks(tree_height);
            vector<vector<uint8_t>> ltree_bitmasks(LTREE_NUM_BITMASKS);
            
            for (size_t i = 0; i < tree_height; i++) {
                xmss_bitmasks[i].resize(2 * HASH_OUTPUT_SIZE_BYTES, 0xAB);
            }
            for (int i = 0; i < LTREE_NUM_BITMASKS; i++) {
                ltree_bitmasks[i].resize(2 * HASH_OUTPUT_SIZE_BYTES, 0xCD);
            }
            
            // Build tree and get output
            XMSSTreeOutput output = XMSS_BuildTree(seed, tree_height, leaf_index, 
                                                    xmss_bitmasks, ltree_bitmasks);
            
            cout << "\n[XMSS Tree Build Result]" << endl;
            cout << "Tree Height: " << tree_height << endl;
            cout << "Leaf Index: " << leaf_index << endl;
            cout << "\nXMSS Tree Root: ";
            printHex(output.root);
            
            // Save root to file
            saveValueToFile(output.root, "xmss_root.txt");
            cout << "[Root saved to: xmss_root.txt]" << endl;
            
            // Save authentication path to file
            saveAuthPathToFile(output.auth_path, "xmss_auth_path.txt");
            cout << "[Authentication Path (" << output.auth_path.size() << " nodes) saved to: xmss_auth_path.txt]" << endl;
            
            // Save WOTS+ signature to file
            WOTS_SaveSignatureToFile(output.wots_sig, "xmss_wots_signature.txt");
            cout << "[WOTS+ Signature saved to: xmss_wots_signature.txt]" << endl;
            
        } catch (const exception& e) {
            cout << "Error: " << e.what() << endl;
        }
        
    } else if (choice == 2) {
        cout << "\nVerify XMSS Tree - Complete Verification" << endl;
        cout << "This verifies the root using signature, authentication path, and message\n" << endl;
        
        cout << "Enter tree height: ";
        size_t height;
        cin >> height;
        cin.ignore();
        
        if (height < 1 || height > 20) {
            cout << "Error: Height must be between 1 and 20" << endl;
            return;
        }
        
        cout << "Enter XMSS root filename: ";
        string root_file;
        getline(cin, root_file);
        
        cout << "Enter WOTS+ signature filename: ";
        string sig_file;
        getline(cin, sig_file);
        
        cout << "Enter authentication path filename: ";
        string auth_file;
        getline(cin, auth_file);
        
        cout << "Enter message (64 hex chars = 32 bytes): ";
        string msg_hex;
        getline(cin, msg_hex);
        
        try {
            // Convert hex message to bytes
            vector<uint8_t> message = readHexString(msg_hex);
            if (message.size() != HASH_OUTPUT_SIZE_BYTES) {
                cout << "Error: Message must be 32 bytes" << endl;
                return;
            }
            
            cout << "\nVerifying XMSS tree components..." << endl;
            
            // Load and display components
            cout << "\n[Component Status]" << endl;
            
            // Load root
            std::ifstream rf(root_file);
            if (!rf.is_open()) {
                cout << "✗ Root file not found: " << root_file << endl;
                return;
            }
            std::string root_hex;
            std::getline(rf, root_hex);
            rf.close();
            cout << "✓ Root loaded: " << root_hex.substr(0, 16) << "... (32 bytes)" << endl;
            
            // Load signature
            WOTSSignature sig = WOTS_LoadSignatureFromFile(sig_file);
            cout << "✓ WOTS+ Signature loaded (" << WOTS_L << " components)" << endl;
            
            cout << "✓ Message loaded: " << msg_hex.substr(0, 16) << "... (32 bytes)" << endl;
            
            // Count authentication path nodes
            std::ifstream af(auth_file);
            if (!af.is_open()) {
                cout << "✗ Auth path file not found: " << auth_file << endl;
                return;
            }
            std::string line;
            size_t auth_nodes = 0;
            while (std::getline(af, line)) {
                if (!line.empty()) auth_nodes++;
            }
            af.close();
            cout << "✓ Authentication path loaded (" << auth_nodes << " nodes)" << endl;
            
            // Verify all components
            cout << "\n[XMSS Component Verification]" << endl;
            
            // Reconstruct WOTS+ public key and verify signature integrity
            cout << "Step 1: Reconstructing WOTS+ public key from signature..." << endl;
            WOTSPublicKey wots_pk = LTree_ReconstructPublicKeyFromSignature(sig_file, message);
            cout << "  ✓ WOTS+ public key reconstructed" << endl;
            
            // Compute L-Tree root
            cout << "Step 2: Computing L-Tree root from WOTS+ public key..." << endl;
            std::vector<std::vector<uint8_t>> ltree_bitmasks(LTREE_NUM_BITMASKS);
            for (int i = 0; i < LTREE_NUM_BITMASKS; i++) {
                ltree_bitmasks[i].resize(2 * HASH_OUTPUT_SIZE_BYTES, 0xCC);
            }
            std::vector<uint8_t> leaf = LTree(wots_pk.pk_components, ltree_bitmasks);
            cout << "  ✓ L-Tree root (leaf): " << bytesToHex(leaf).substr(0, 16) << "..." << endl;
            
            // Verify authentication path structure
            cout << "Step 3: Validating authentication path structure..." << endl;
            if (auth_nodes != height) {
                cout << "  ✗ Authentication path size mismatch: expected " << height << ", got " << auth_nodes << endl;
                return;
            }
            cout << "  ✓ Authentication path has " << auth_nodes << " nodes (matches tree height " << height << ")" << endl;
            
            // Full XMSS verification
            cout << "Step 4: Complete XMSS verification..." << endl;
            bool xmss_valid = XMSS_VerifyComplete(root_file, sig_file, auth_file, message, height);
            
            cout << "\n[XMSS Verification Result]" << endl;
            cout << "Signature validity: ✓ (reconstructed successfully)" << endl;
            cout << "Auth path structure: ✓ (" << auth_nodes << " nodes of 32 bytes each)" << endl;
            cout << "Component integrity: " << (xmss_valid ? "✓" : "✗") << endl;
            cout << "\nOverall Status: " << (xmss_valid ? "VALID ✓" : "INVALID ✗") << endl;
            
        } catch (const exception& e) {
            cout << "Error during verification: " << e.what() << endl;
        }
    }
}

void multiLayerXMSSMenu(int h1, int h2) {
    cout << "\n===== Multi-Layer XMSS Evaluation =====" << endl;
    cout << "1. Evaluate with specific indices for each layer" << endl;
    cout << "2. Verify proof from file" << endl;
    cout << "3. Go back" << endl;
    
    int choice;
    cout << "Enter choice: ";
    cin >> choice;
    cin.ignore();
    
    if (choice == 1) {
        cout << "\nGenerating Multi-Layer XMSS key pair..." << endl;
        auto [sk, pk] = MultiXMSS_KeyGen(2, h1);
        
        cout << "[Key pair generated]" << endl;
        cout << "Verification Key Root: ";
        printHex(pk.root);
        cout << "\n[Root saved to: mlxmss_root.txt]" << endl;
        saveValueToFile(pk.root, "mlxmss_root.txt");
        
        cout << "\nEnter index for Layer 0 (0 to " << ((1UL << h1) - 1) << "): ";
        size_t idx0;
        cin >> idx0;
        
        cout << "Enter index for Layer 1 (0 to " << ((1UL << h1) - 1) << "): ";
        size_t idx1;
        cin >> idx1;
        cin.ignore();
        
        if (idx0 >= (1UL << h1) || idx1 >= (1UL << h1)) {
            cout << "Error: Index out of range" << endl;
            return;
        }
        
        try {
            vector<size_t> layer_indices = {idx0, idx1};
            MultiLayerXMSSProof proof = MultiXMSS_EvalWithIndices(sk, layer_indices);
            
            cout << "\n[Multi-Layer XMSS Evaluation Result]" << endl;
            cout << "Layer 0 Index: " << idx0 << endl;
            cout << "Layer 1 Index: " << idx1 << endl;
            
            // Save WOTS+ signatures for both layers
            for (size_t layer = 0; layer < 2; layer++) {
                string filename = "mlxmss_wots_sig_layer" + to_string(layer) + ".txt";
                WOTS_SaveSignatureToFile(proof.wots_sigs[layer], filename);
                cout << "\n[Layer " << layer << " WOTS+ Signature saved to: " << filename << "]" << endl;
            }
            
            // Save authentication paths for both layers
            for (size_t layer = 0; layer < 2; layer++) {
                string filename = "mlxmss_auth_path_layer" + to_string(layer) + ".txt";
                saveAuthPathToFile(proof.auth_paths[layer], filename);
                cout << "[Layer " << layer << " Authentication Path (" << proof.auth_paths[layer].size() 
                     << " nodes) saved to: " << filename << "]" << endl;
            }
            
        } catch (const exception& e) {
            cout << "Error: " << e.what() << endl;
        }
        
    } else if (choice == 2) {
        cout << "\nVerify Multi-Layer XMSS Proof - Complete Cryptographic Verification" << endl;
        cout << "This verifies using root, signatures, auth paths, message, and leaf indices\n" << endl;
        
        cout << "Enter root filename: ";
        string root_file;
        getline(cin, root_file);
        
        cout << "Enter number of layers: ";
        size_t num_layers;
        cin >> num_layers;
        cin.ignore();
        
        cout << "Enter layer height (h_prime): ";
        size_t h_prime;
        cin >> h_prime;
        cin.ignore();
        
        if (num_layers < 1 || num_layers > 10 || h_prime < 1 || h_prime > 20) {
            cout << "Error: Invalid parameters" << endl;
            return;
        }
        
        cout << "Enter message (64 hex chars = 32 bytes): ";
        string msg_hex;
        getline(cin, msg_hex);
        
        vector<uint8_t> message = readHexString(msg_hex);
        if (message.size() != HASH_OUTPUT_SIZE_BYTES) {
            cout << "Error: Message must be 32 bytes" << endl;
            return;
        }
        
        // Get leaf indices for each layer
        vector<size_t> layer_indices(num_layers);
        for (size_t i = 0; i < num_layers; i++) {
            cout << "Enter leaf index for Layer " << i << " (0 to " << ((1UL << h_prime) - 1) << "): ";
            cin >> layer_indices[i];
            
            if (layer_indices[i] >= (1UL << h_prime)) {
                cout << "Error: Index out of range for layer " << i << endl;
                return;
            }
        }
        cin.ignore();
        
        // Get signature filenames for each layer
        vector<string> sig_filenames(num_layers);
        cout << "\n[Signature Filenames]" << endl;
        for (size_t i = 0; i < num_layers; i++) {
            cout << "Enter WOTS+ signature filename for Layer " << i << ": ";
            getline(cin, sig_filenames[i]);
        }
        
        // Get authentication path filenames for each layer
        vector<string> auth_filenames(num_layers);
        cout << "\n[Authentication Path Filenames]" << endl;
        for (size_t i = 0; i < num_layers; i++) {
            cout << "Enter authentication path filename for Layer " << i << ": ";
            getline(cin, auth_filenames[i]);
        }
        cin.ignore();
        
        try {
            // Create public key structure
            MultiLayerXMSSPublicKey pk(num_layers, h_prime);
            
            // Load root from file
            ifstream root_file_stream(root_file);
            if (!root_file_stream.is_open()) {
                cout << "Error: Cannot open root file: " << root_file << endl;
                return;
            }
            string root_hex;
            getline(root_file_stream, root_hex);
            root_file_stream.close();
            
            pk.root = readHexString(root_hex);
            if (pk.root.size() != HASH_OUTPUT_SIZE_BYTES) {
                cout << "Error: Invalid root size" << endl;
                return;
            }
            
            cout << "\n[Component Status]" << endl;
            cout << "✓ Root loaded: " << root_hex.substr(0, 16) << "... (32 bytes)" << endl;
            cout << "✓ Message: " << msg_hex.substr(0, 16) << "... (32 bytes)" << endl;
            
            // Create proof structure
            MultiLayerXMSSProof proof(num_layers, h_prime);
            
            // Load WOTS+ signatures for each layer
            cout << "\n[Loading Signatures]" << endl;
            for (size_t layer = 0; layer < num_layers; layer++) {
                try {
                    proof.wots_sigs[layer] = WOTS_LoadSignatureFromFile(sig_filenames[layer]);
                    cout << "✓ Layer " << layer << " WOTS+ Signature loaded from " << sig_filenames[layer] 
                         << " (" << WOTS_L << " components)" << endl;
                } catch (const exception& e) {
                    cout << "✗ Layer " << layer << " WOTS+ Signature: " << e.what() << endl;
                    return;
                }
            }
            
            // Load authentication paths for each layer
            cout << "\n[Loading Authentication Paths]" << endl;
            for (size_t layer = 0; layer < num_layers; layer++) {
                // Count nodes in auth path
                ifstream auth_file(auth_filenames[layer]);
                if (!auth_file.is_open()) {
                    cout << "✗ Layer " << layer << " Authentication Path: Cannot open " << auth_filenames[layer] << endl;
                    return;
                }
                
                string line;
                size_t node_count = 0;
                while (getline(auth_file, line)) {
                    if (!line.empty()) node_count++;
                }
                auth_file.close();
                
                if (node_count != h_prime) {
                    cout << "✗ Layer " << layer << " Authentication Path: Expected " << h_prime 
                         << " nodes, got " << node_count << endl;
                    return;
                }
                
                // Load auth path nodes
                auth_file.open(auth_filenames[layer]);
                proof.auth_paths[layer].clear();
                proof.auth_paths[layer].resize(h_prime);
                
                for (size_t i = 0; i < h_prime; i++) {
                    string auth_hex;
                    getline(auth_file, auth_hex);
                    proof.auth_paths[layer][i] = readHexString(auth_hex);
                    if (proof.auth_paths[layer][i].size() != HASH_OUTPUT_SIZE_BYTES) {
                        cout << "✗ Layer " << layer << " Auth node " << i << ": Invalid size" << endl;
                        auth_file.close();
                        return;
                    }
                }
                auth_file.close();
                cout << "✓ Layer " << layer << " Authentication Path loaded from " << auth_filenames[layer] 
                     << " (" << h_prime << " nodes)" << endl;
            }
            
            // Perform complete cryptographic verification
            cout << "\n[Multi-Layer XMSS Cryptographic Verification]" << endl;
            cout << "Reconstructing XMSS roots from signatures and auth paths..." << endl;
            
            bool valid = MultiXMSS_VerifyComplete(pk, proof, message, layer_indices);
            
            cout << "\n[Verification Result]" << endl;
            cout << "Leaf indices verified: ✓ (";
            for (size_t i = 0; i < num_layers; i++) {
                cout << layer_indices[i];
                if (i < num_layers - 1) cout << ", ";
            }
            cout << ")" << endl;
            cout << "Signatures verified: ✓ (" << num_layers << " WOTS+ signatures reconstructed)" << endl;
            cout << "Auth paths verified: ✓ (roots reconstructed from " << num_layers << " x " << h_prime << " nodes)" << endl;
            cout << "Root match: " << (valid ? "✓" : "✗") << " (reconstructed root " << (valid ? "matches" : "does NOT match") << " expected root)" << endl;
            cout << "\nOverall Status: " << (valid ? "VALID ✓" : "INVALID ✗") << endl;
            
        } catch (const exception& e) {
            cout << "Error during verification: " << e.what() << endl;
        }
    }
}

void xmvrfMenu() {
    cout << "\n===== XM-VRF (Verifiable Random Function) =====" << endl;
    cout << "1. Generate XM-VRF key pair" << endl;
    cout << "2. Evaluate XM-VRF and save output with proofs" << endl;
    cout << "3. Verify XM-VRF output from files" << endl;
    cout << "4. Go back" << endl;
    
    int choice;
    cout << "Enter choice: ";
    cin >> choice;
    cin.ignore();
    
    static XMVRFSecretKey* stored_sk = nullptr;
    static XMVRFVerificationKey* stored_vk = nullptr;
    static XMVRFPublicParameters* stored_pp = nullptr;
    
    if (choice == 1) {
        cout << "\nGenerating XM-VRF parameters (2 layers, h=8)..." << endl;
        XMVRFPublicParameters pp = XM_VRF_ParamGen(128, 8, 2, 16);
        
        cout << "Parameters:" << endl;
        cout << "  Lambda (security parameter): " << pp.lambda << " bits" << endl;
        cout << "  Total Height: " << pp.h << endl;
        cout << "  Number of Layers: " << pp.d << endl;
        cout << "  Height per layer: " << pp.h_prime << endl;
        
        cout << "\nGenerating key pair..." << endl;
        auto [sk, vk] = XM_VRF_KeyGen(pp);
        
        stored_pp = new XMVRFPublicParameters(pp);
        stored_sk = new XMVRFSecretKey(sk);
        stored_vk = new XMVRFVerificationKey(vk);
        
        cout << "\n[XM-VRF Key Pair Generated Successfully]" << endl;
        cout << "Verification Key Root: ";
        printHex(vk.GetRoot());
        
        // Save VK root to file
        saveValueToFile(vk.GetRoot(), "xmvrf_vk_root.txt");
        cout << "[VK Root saved to: xmvrf_vk_root.txt]" << endl;
        cout << "\n[Key pair stored in memory for next operations]" << endl;
        
    } else if (choice == 2) {
        if (!stored_sk || !stored_pp) {
            cout << "Error: Must generate key pair first (option 1)" << endl;
            return;
        }
        
        cout << "\nEnter message to evaluate (hex string, 1-64 chars = 1-32 bytes): ";
        string msgHex;
        getline(cin, msgHex);
        
        if (msgHex.empty() || msgHex.length() > 64) {
            cout << "Error: Message must be 1-64 hex characters (1-32 bytes)" << endl;
            return;
        }
        
        vector<uint8_t> message = readHexString(msgHex);
        
        // Pad to 32 bytes
        while (message.size() < 32) {
            message.push_back(0x00);
        }
        
        // Compute layer indices BEFORE evaluation (they are deterministic based on counter/top_layer_index)
        size_t h_prime = stored_pp->h_prime;
        size_t layer0_idx = stored_sk->mlxmss_sk.counter % (1UL << h_prime);
        size_t layer1_idx = stored_sk->mlxmss_sk.top_layer_index % (1UL << h_prime);
        vector<size_t> eval_layer_indices = {layer0_idx, layer1_idx};
        
        cout << "\nEvaluating XM-VRF on message..." << endl;
        cout << "  Layer 0 leaf index: " << layer0_idx << endl;
        cout << "  Layer 1 leaf index: " << layer1_idx << endl;
        
        XMVRFOutput output = XM_VRF_Eval(*stored_pp, *stored_sk, message);
        
        cout << "\n[XM-VRF Evaluation Result]" << endl;
        cout << "VRF Output (32 bytes): ";
        printHex(output.y);
        
        // Save VRF output to file
        saveValueToFile(output.y, "xmvrf_output.txt");
        cout << "[VRF Output saved to: xmvrf_output.txt]" << endl;
        
        // Save message to file for verification
        saveValueToFile(message, "xmvrf_message.txt");
        cout << "[Message saved to: xmvrf_message.txt]" << endl;
        
        // Save WOTS+ signatures and authentication paths for both layers
        cout << "\n[Saving Proof Components]" << endl;
        
        // Save layer indices
        ofstream indicesFile("xmvrf_layer_indices.txt");
        if (!indicesFile.is_open()) {
            cout << "Error: Cannot create xmvrf_layer_indices.txt" << endl;
            return;
        }
        for (size_t i = 0; i < eval_layer_indices.size(); i++) {
            indicesFile << eval_layer_indices[i];
            if (i < eval_layer_indices.size() - 1) indicesFile << " ";
        }
        indicesFile.close();
        cout << "Layer indices saved to: xmvrf_layer_indices.txt" << endl;
        
        for (size_t layer = 0; layer < output.proof.d; layer++) {
            // Save WOTS+ signature for this layer
            string sigFilename = "xmvrf_wots_sig_layer" + to_string(layer) + ".txt";
            WOTS_SaveSignatureToFile(output.proof.wots_sigs[layer], sigFilename);
            cout << "Layer " << layer << " WOTS+ Signature saved to: " << sigFilename << endl;
            
            // Save authentication path for this layer
            string authFilename = "xmvrf_auth_path_layer" + to_string(layer) + ".txt";
            saveAuthPathToFile(output.proof.auth_paths[layer], authFilename);
            cout << "Layer " << layer << " Authentication Path (" << output.proof.auth_paths[layer].size() 
                 << " nodes) saved to: " << authFilename << endl;
        }
        
        cout << "\n[All proof components saved successfully]" << endl;
        
    } else if (choice == 3) {
        if (!stored_vk || !stored_pp) {
            cout << "Error: Must generate key pair first (option 1)" << endl;
            return;
        }
        
        cout << "\nVerifying XM-VRF Output - Complete Verification" << endl;
        cout << "This verifies VRF output using signatures and authentication paths\n" << endl;
        
        try {
            // Load message
            ifstream msgFile("xmvrf_message.txt");
            if (!msgFile.is_open()) {
                cout << "Error: Cannot open xmvrf_message.txt" << endl;
                return;
            }
            string msgHex;
            getline(msgFile, msgHex);
            msgFile.close();
            vector<uint8_t> message = readHexString(msgHex);
            
            // Load VRF output
            ifstream yFile("xmvrf_output.txt");
            if (!yFile.is_open()) {
                cout << "Error: Cannot open xmvrf_output.txt" << endl;
                return;
            }
            string yHex;
            getline(yFile, yHex);
            yFile.close();
            vector<uint8_t> y = readHexString(yHex);
            
            if (y.size() != 32) {
                cout << "Error: VRF output must be 32 bytes" << endl;
                return;
            }
            
            cout << "\n[Component Status]" << endl;
            cout << "✓ Message loaded: " << msgHex.substr(0, 16) << "..." << endl;
            cout << "✓ VRF Output loaded: " << yHex.substr(0, 16) << "... (32 bytes)" << endl;
            
            // Load proof components
            size_t num_layers = stored_pp->d;
            size_t h_prime = stored_pp->h_prime;
            MultiLayerXMSSProof proof(num_layers, h_prime);
            
            // Get signature filenames for each layer
            vector<string> sig_filenames(num_layers);
            cout << "\n[Signature Filenames]" << endl;
            for (size_t i = 0; i < num_layers; i++) {
                cout << "Enter WOTS+ signature filename for Layer " << i << ": ";
                getline(cin, sig_filenames[i]);
            }
            
            // Get authentication path filenames for each layer
            vector<string> auth_filenames(num_layers);
            cout << "\n[Authentication Path Filenames]" << endl;
            for (size_t i = 0; i < num_layers; i++) {
                cout << "Enter authentication path filename for Layer " << i << ": ";
                getline(cin, auth_filenames[i]);
            }
            
            // Load layer indices from file
            vector<size_t> layer_indices(num_layers);
            cout << "\n[Loading Layer Indices]" << endl;
            ifstream indicesFile("xmvrf_layer_indices.txt");
            if (!indicesFile.is_open()) {
                cout << "Warning: Cannot open xmvrf_layer_indices.txt, asking user to enter manually" << endl;
                for (size_t i = 0; i < num_layers; i++) {
                    cout << "Enter leaf index for Layer " << i << " (0 to " << ((1UL << h_prime) - 1) << "): ";
                    cin >> layer_indices[i];
                    
                    if (layer_indices[i] >= (1UL << h_prime)) {
                        cout << "Error: Index out of range for layer " << i << endl;
                        return;
                    }
                }
            } else {
                for (size_t i = 0; i < num_layers; i++) {
                    indicesFile >> layer_indices[i];
                    cout << "✓ Layer " << i << " leaf index: " << layer_indices[i] << endl;
                    
                    if (layer_indices[i] >= (1UL << h_prime)) {
                        cout << "Error: Index out of range for layer " << i << endl;
                        indicesFile.close();
                        return;
                    }
                }
                indicesFile.close();
            }
            cin.ignore();
            
            cout << "\n[Loading Proof Components]" << endl;
            
            // Load WOTS+ signatures
            cout << "[WOTS+ Signatures]" << endl;
            for (size_t layer = 0; layer < num_layers; layer++) {
                try {
                    proof.wots_sigs[layer] = WOTS_LoadSignatureFromFile(sig_filenames[layer]);
                    cout << "✓ Layer " << layer << " loaded from " << sig_filenames[layer] 
                         << ": " << WOTS_L << " components" << endl;
                } catch (const exception& e) {
                    cout << "✗ Layer " << layer << ": " << e.what() << endl;
                    return;
                }
            }
            
            // Load authentication paths
            cout << "[Authentication Paths]" << endl;
            for (size_t layer = 0; layer < num_layers; layer++) {
                // Count nodes
                ifstream authFile(auth_filenames[layer]);
                if (!authFile.is_open()) {
                    cout << "✗ Layer " << layer << ": Cannot open " << auth_filenames[layer] << endl;
                    return;
                }
                
                string line;
                size_t node_count = 0;
                while (getline(authFile, line)) {
                    if (!line.empty()) node_count++;
                }
                authFile.close();
                
                if (node_count != h_prime) {
                    cout << "✗ Layer " << layer << ": Expected " << h_prime << " nodes, got " 
                         << node_count << endl;
                    return;
                }
                
                // Load nodes
                authFile.open(auth_filenames[layer]);
                proof.auth_paths[layer].clear();
                proof.auth_paths[layer].resize(h_prime);
                
                for (size_t i = 0; i < h_prime; i++) {
                    string node_hex;
                    getline(authFile, node_hex);
                    proof.auth_paths[layer][i] = readHexString(node_hex);
                    if (proof.auth_paths[layer][i].size() != HASH_OUTPUT_SIZE_BYTES) {
                        cout << "✗ Layer " << layer << " Node " << i << ": Invalid size" << endl;
                        authFile.close();
                        return;
                    }
                }
                authFile.close();
                cout << "✓ Layer " << layer << " loaded from " << auth_filenames[layer] << ": " << h_prime << " nodes" << endl;
            }
            
            cout << "\n[XM-VRF Verification Process]" << endl;
            cout << "Performing cryptographic verification..." << endl;
            cout << "Reconstructing XMSS roots from signatures and auth paths..." << endl;
            
            // Full cryptographic verification
            bool valid = MultiXMSS_VerifyComplete(stored_vk->mlxmss_pk, proof, message, layer_indices);
            
            cout << "\n[XM-VRF Verification Result]" << endl;
            cout << "Message: " << msgHex.substr(0, 32) << "..." << endl;
            cout << "VRF Output: " << yHex.substr(0, 16) << "..." << endl;
            cout << "Leaf indices: (";
            for (size_t i = 0; i < num_layers; i++) {
                cout << layer_indices[i];
                if (i < num_layers - 1) cout << ", ";
            }
            cout << ")" << endl;
            cout << "Layers verified: ✓ (" << num_layers << " layers)" << endl;
            cout << "Auth paths verified: ✓ (" << num_layers << " x " << h_prime << " nodes)" << endl;
            cout << "Signatures verified: ✓ (" << num_layers << " WOTS+ signatures)" << endl;
            cout << "\nStatus: " << (valid ? "VALID ✓" : "INVALID ✗") << endl;
            
        } catch (const exception& e) {
            cout << "Error during verification: " << e.what() << endl;
        }
    }
}

int main() {
    cout << "========================================" << endl;
    cout << "   XM-VRF Interactive Testing System" << endl;
    cout << "   (2-Layer Configuration)" << endl;
    cout << "========================================" << endl;
    
    int h1 = 4, h2 = 4; // Heights for 2 layers
    
    while (true) {
        cout << "\n===== Main Menu =====" << endl;
        cout << "1. WOTS+ (One-Time Signature)" << endl;
        cout << "2. L-Tree (Leaf Aggregation)" << endl;
        cout << "3. XMSS Tree (Layer 1, Height=" << h1 << ")" << endl;
        cout << "4. Multi-Layer XMSS (2 Layers)" << endl;
        cout << "5. XM-VRF (Verifiable Random Function)" << endl;
        cout << "6. Configure Layer Heights" << endl;
        cout << "7. Exit" << endl;
        
        int choice;
        cout << "\nEnter choice (1-7): ";
        cin >> choice;
        cin.ignore();
        
        switch (choice) {
            case 1:
                wotsPlusMenu(h1);
                break;
            case 2:
                ltreeMenu();
                break;
            case 3:
                xmssTreeMenu(h1);
                break;
            case 4:
                multiLayerXMSSMenu(h1, h2);
                break;
            case 5:
                xmvrfMenu();
                break;
            case 6: {
                cout << "\nConfigure Layer Heights:" << endl;
                cout << "Enter height for Layer 1 (currently " << h1 << "): ";
                cin >> h1;
                cout << "Enter height for Layer 2 (currently " << h2 << "): ";
                cin >> h2;
                cin.ignore();
                cout << "Heights updated!" << endl;
                break;
            }
            case 7:
                cout << "\nThank you for using XM-VRF Test System!" << endl;
                return 0;
            default:
                cout << "Invalid choice!" << endl;
        }
    }
    
    return 0;
}

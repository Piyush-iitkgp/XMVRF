#include <iostream>
#include <fstream>
#include <vector>
#include <cstring>
#include "../include/xm_vrf.h"
#include "../include/crypto_utils.h"

using namespace std;

vector<uint8_t> readHexString(const string& hex_str) {
    vector<uint8_t> result;
    for (size_t i = 0; i < hex_str.length(); i += 2) {
        string byte_str = hex_str.substr(i, 2);
        uint8_t byte = (uint8_t)strtol(byte_str.c_str(), nullptr, 16);
        result.push_back(byte);
    }
    return result;
}

string readStringFromFile(const string& filename) {
    ifstream file(filename);
    if (!file.is_open()) {
        throw runtime_error("Cannot open file: " + filename);
    }
    string content;
    getline(file, content);
    file.close();
    return content;
}

int main() {
    try {
        cout << "\n=== Direct XM-VRF Verification Test ===" << endl;
        
        // Load message
        cout << "\nLoading message..." << endl;
        string msgHex = readStringFromFile("xmvrf_message.txt");
        vector<uint8_t> message = readHexString(msgHex);
        cout << "Message loaded: " << msgHex.substr(0, 16) << "... (" << message.size() << " bytes)" << endl;
        
        // Load VRF output
        cout << "\nLoading VRF output..." << endl;
        string yHex = readStringFromFile("xmvrf_output.txt");
        vector<uint8_t> y = readHexString(yHex);
        cout << "VRF output loaded: " << yHex.substr(0, 16) << "... (" << y.size() << " bytes)" << endl;
        
        // Load verification key root
        cout << "\nLoading verification key root..." << endl;
        string vkHex = readStringFromFile("xmvrf_vk_root.txt");
        vector<uint8_t> vk_root = readHexString(vkHex);
        cout << "VK root loaded: " << vkHex.substr(0, 16) << "... (" << vk_root.size() << " bytes)" << endl;
        
        // Load layer indices
        cout << "\nLoading layer indices..." << endl;
        vector<size_t> layer_indices;
        ifstream indicesFile("xmvrf_layer_indices.txt");
        if (indicesFile.is_open()) {
            size_t idx;
            while (indicesFile >> idx) {
                layer_indices.push_back(idx);
            }
            indicesFile.close();
            cout << "Layer indices loaded: ";
            for (size_t i = 0; i < layer_indices.size(); i++) {
                cout << layer_indices[i];
                if (i < layer_indices.size() - 1) cout << ", ";
            }
            cout << endl;
        }
        
        // Load signatures
        cout << "\nLoading WOTS+ signatures..." << endl;
        vector<WOTSSignature> wots_sigs(2);
        for (size_t layer = 0; layer < 2; layer++) {
            string sigFile = "xmvrf_wots_sig_layer" + to_string(layer) + ".txt";
            string sigHex = readStringFromFile(sigFile);
            
            // Parse signature (67 components of 32 bytes each)
            wots_sigs[layer].sig_components.resize(WOTS_L);
            size_t pos = 0;
            for (size_t i = 0; i < WOTS_L; i++) {
                string comp = sigHex.substr(pos, 64);
                wots_sigs[layer].sig_components[i] = readHexString(comp);
                pos += 65; // 64 hex chars + 1 space
            }
            cout << "  Layer " << layer << ": " << WOTS_L << " components loaded" << endl;
        }
        
        // Load auth paths
        cout << "\nLoading authentication paths..." << endl;
        vector<vector<vector<uint8_t>>> auth_paths(2);
        for (size_t layer = 0; layer < 2; layer++) {
            string authFile = "xmvrf_auth_path_layer" + to_string(layer) + ".txt";
            ifstream file(authFile);
            if (!file.is_open()) {
                throw runtime_error("Cannot open file: " + authFile);
            }
            
            auth_paths[layer].clear();
            string line;
            while (getline(file, line)) {
                if (!line.empty()) {
                    auth_paths[layer].push_back(readHexString(line));
                }
            }
            file.close();
            cout << "  Layer " << layer << ": " << auth_paths[layer].size() << " nodes loaded" << endl;
        }
        
        // Create proof
        cout << "\nCreating proof structure..." << endl;
        MultiLayerXMSSProof proof(2, 4);
        proof.wots_sigs = wots_sigs;
        proof.auth_paths = auth_paths;
        cout << "Proof created with " << proof.wots_sigs.size() << " layers" << endl;
        
        // Create public key
        cout << "\nCreating public key structure..." << endl;
        MultiLayerXMSSPublicKey pk(2, 4);
        pk.root = vk_root;
        cout << "Public key created with root: " << vkHex.substr(0, 16) << "..." << endl;
        
        // Verify
        cout << "\n=== Running Verification ===" << endl;
        bool valid = MultiXMSS_VerifyComplete(pk, proof, message, layer_indices);
        
        cout << "\n=== Verification Result ===" << endl;
        cout << "Status: " << (valid ? "✓ VALID" : "✗ INVALID") << endl;
        
        if (valid) {
            cout << "\nVerification PASSED - Root was successfully reconstructed!" << endl;
        } else {
            cout << "\nVerification FAILED - Root reconstruction did not match" << endl;
            cout << "This could be due to:" << endl;
            cout << "  1. Incorrect layer indices" << endl;
            cout << "  2. Corrupted signature or auth path data" << endl;
            cout << "  3. Bug in verification logic" << endl;
        }
        
        return valid ? 0 : 1;
        
    } catch (const exception& e) {
        cerr << "ERROR: " << e.what() << endl;
        return 2;
    }
}

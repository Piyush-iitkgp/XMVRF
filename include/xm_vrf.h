#ifndef XM_VRF_H
#define XM_VRF_H

#include "multilayer_xmss.h"
#include <vector>
#include <cstdint>
#include <cstddef>

// XM-VRF public parameters
struct XMVRFPublicParameters {
    size_t lambda;
    size_t h;
    size_t d;
    size_t h_prime;
    size_t w;
    size_t m;
    size_t l1;
    size_t l2;
    size_t l;
    
    XMVRFPublicParameters();
    XMVRFPublicParameters(size_t lambda_in, size_t h_in, size_t d_in, size_t w_in);
};

// XM-VRF secret key
struct XMVRFSecretKey {
    MultiLayerXMSSSecretKey mlxmss_sk;
    
    XMVRFSecretKey(const MultiLayerXMSSSecretKey& mlxmss_sk_in);
};

// XM-VRF verification key (public key)
struct XMVRFVerificationKey {
    MultiLayerXMSSPublicKey mlxmss_pk;
    
    XMVRFVerificationKey(const MultiLayerXMSSPublicKey& mlxmss_pk_in);
    const std::vector<uint8_t>& GetRoot() const;
};

// VRF output (signed message + proof)
struct XMVRFOutput {
    std::vector<uint8_t> y;
    MultiLayerXMSSProof proof;
    
    XMVRFOutput();
    XMVRFOutput(const std::vector<uint8_t>& y_in, const MultiLayerXMSSProof& proof_in);
    
    std::vector<uint8_t> Serialize() const;
    static XMVRFOutput Deserialize(const std::vector<uint8_t>& data);
};

// Generate XM-VRF public parameters
XMVRFPublicParameters XM_VRF_ParamGen(size_t lambda = 128,
                                      size_t h = 40,
                                      size_t d = 4,
                                      size_t w = 16);

// Generate XM-VRF key pair
std::pair<XMVRFSecretKey, XMVRFVerificationKey>
XM_VRF_KeyGen(const XMVRFPublicParameters& pp);

// Evaluate XM-VRF on input message
XMVRFOutput XM_VRF_Eval(const XMVRFPublicParameters& pp,
                        XMVRFSecretKey& sk,
                        const std::vector<uint8_t>& x);

// Verify XM-VRF output
bool XM_VRF_Verify(const XMVRFPublicParameters& pp,
                   const XMVRFVerificationKey& vk,
                   const std::vector<uint8_t>& x,
                   const std::vector<uint8_t>& y,
                   const MultiLayerXMSSProof& proof);

#endif // XM_VRF_H
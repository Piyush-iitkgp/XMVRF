cmake_minimum_required(VERSION 3.10)
project(XM_VRF)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find OpenSSL for crypto functions
find_package(OpenSSL REQUIRED)
include_directories(${OPENSSL_INCLUDE_DIR})

# Include directories
include_directories(${CMAKE_SOURCE_DIR}/include)

# ============================================================================
# PHASE 1: Crypto Utilities
# ============================================================================

add_library(crypto_utils 
    src/crypto_utils.cpp
    include/crypto_utils.h
)
target_link_libraries(crypto_utils ${OPENSSL_LIBRARIES})



# ============================================================================
# PHASE 2: WOTS+ One-Time Signatures
# ============================================================================

add_library(wots_plus
    src/wots_plus.cpp
    include/wots_plus.h
)
target_link_libraries(wots_plus crypto_utils ${OPENSSL_LIBRARIES})

# ============================================================================
# PHASE 3a: L-Tree (Leaf Accumulator)
# ============================================================================

add_library(ltree
    src/ltree.cpp
    include/ltree.h
)
target_link_libraries(ltree wots_plus crypto_utils ${OPENSSL_LIBRARIES})

# ============================================================================
# PHASE 3b: XMSS Tree
# ============================================================================

add_library(xmss_tree
    src/xmss_tree.cpp
    include/xmss_tree.h
)
target_link_libraries(xmss_tree ltree wots_plus crypto_utils ${OPENSSL_LIBRARIES})

# ============================================================================
# PHASE 4: Multi-Layer XMSS
# ============================================================================

add_library(multilayer_xmss
    src/multilayer_xmss.cpp
    include/multilayer_xmss.h
)
target_link_libraries(multilayer_xmss xmss_tree ltree wots_plus crypto_utils ${OPENSSL_LIBRARIES})

# ============================================================================
# PHASE 5: XM-VRF (Complete VRF System)
# ============================================================================

add_library(xm_vrf
    src/xm_vrf.cpp
    include/xm_vrf.h
)
target_link_libraries(xm_vrf multilayer_xmss xmss_tree ltree wots_plus crypto_utils ${OPENSSL_LIBRARIES})





# Main executable
add_executable(xmvrf
    src/main.cpp
)
target_link_libraries(xmvrf xm_vrf multilayer_xmss xmss_tree ltree wots_plus crypto_utils ${OPENSSL_LIBRARIES})

# ============================================================================
# Compiler flags for better warnings
# ============================================================================

if(MSVC)
    target_compile_options(crypto_utils PRIVATE /W4)
    target_compile_options(wots_plus PRIVATE /W4)
    target_compile_options(ltree PRIVATE /W4)
    target_compile_options(xmss_tree PRIVATE /W4)
    target_compile_options(multilayer_xmss PRIVATE /W4)
    target_compile_options(xm_vrf PRIVATE /W4)
    target_compile_options(xmvrf PRIVATE /W4)
else()
    target_compile_options(crypto_utils PRIVATE -Wall -Wextra -Wpedantic)
    target_compile_options(wots_plus PRIVATE -Wall -Wextra -Wpedantic)
    target_compile_options(ltree PRIVATE -Wall -Wextra -Wpedantic)
    target_compile_options(xmss_tree PRIVATE -Wall -Wextra -Wpedantic)
    target_compile_options(multilayer_xmss PRIVATE -Wall -Wextra -Wpedantic)
    target_compile_options(xm_vrf PRIVATE -Wall -Wextra -Wpedantic)
    target_compile_options(xmvrf PRIVATE -Wall -Wextra -Wpedantic)
endif()

# ============================================================================
# Print build info
# ============================================================================

message(STATUS "")
message(STATUS "XM-VRF Build Configuration")
message(STATUS "  C++ Standard: 17")
message(STATUS "  OpenSSL: ${OPENSSL_VERSION}")
message(STATUS "  Build Type: ${CMAKE_BUILD_TYPE}")
message(STATUS "  Executable: xmvrf (interactive inspection & verification tool)")
message(STATUS "")

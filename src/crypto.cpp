#include <crypto.hpp>

namespace ntk {

    // ==========================
    //  Generate X25519 Key Pair
    // ==========================

    std::expected<x25519_key_pair,std::string> generate_x25519_key_pair() {
        EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id( EVP_PKEY_X25519, nullptr );
        if ( !pctx ) { 
            return std::unexpected( "Failed to Create PKEY_CTX" );
        }
        if ( EVP_PKEY_keygen_init( pctx ) <= 0 ) { 
            return std::unexpected( "Keygen Init failed" );
        }
        EVP_PKEY *pkey = nullptr;
        if ( EVP_PKEY_keygen( pctx, &pkey ) <= 0 ) { 
            return std::unexpected( "Keygen failed" );
        }
        x25519_key_pair key_pair;
        std::size_t priv_len = key_pair.private_key.size();
        if ( EVP_PKEY_get_raw_private_key( pkey, key_pair.private_key.data(), &priv_len ) <= 0 ) {
            EVP_PKEY_free( pkey );
            EVP_PKEY_CTX_free( pctx );
            return std::unexpected( "Failed to extract private key" );
        }
        std::size_t pub_len = key_pair.public_key.size();
        if ( EVP_PKEY_get_raw_public_key( pkey, key_pair.public_key.data(), &pub_len ) <= 0 ) {
            EVP_PKEY_free( pkey );
            EVP_PKEY_CTX_free( pctx );
            return std::unexpected( "Failed to extract public key" );
        }
        EVP_PKEY_free( pkey );
        EVP_PKEY_CTX_free( pctx );
        return key_pair; 
    }

    // =============================
    //  Derive X25519 Shared Secret
    // =============================

    std::expected<std::vector<uint8_t>,std::string> derive_x25519_shared_secret( const std::array<uint8_t,32>& private_key,
                                                                                 const std::array<uint8_t,32>& peer_public_key ) {
        EVP_PKEY* priv = nullptr;
        EVP_PKEY* pub = nullptr;
        EVP_PKEY_CTX* ctx = nullptr;
        priv = EVP_PKEY_new_raw_private_key( EVP_PKEY_X25519, nullptr, private_key.data(), private_key.size() );
        if ( !priv ) {
            return std::unexpected( "Failed to Create EVP_PKEY from Private Key" );
        }
        pub = EVP_PKEY_new_raw_public_key( EVP_PKEY_X25519, nullptr, peer_public_key.data(), peer_public_key.size() );
        if ( !pub ) {
            EVP_PKEY_free( priv );
            return std::unexpected( "Failed to Create EVP_PKEY from Peer Public Key" );
        }        
        ctx = EVP_PKEY_CTX_new( priv, nullptr );
        if ( !ctx ) {
            EVP_PKEY_free( priv );
            EVP_PKEY_free( pub );
            return std::unexpected( "Failed to Create Context" ); 
        } 
        if ( EVP_PKEY_derive_init( ctx ) <= 0 ) {
            EVP_PKEY_free( priv );
            EVP_PKEY_free( pub );
            return std::unexpected( "EVP_PKEY_derive_init failed" );
        }
        if ( EVP_PKEY_derive_set_peer( ctx, pub) <= 0 ) {
            EVP_PKEY_free( priv );
            EVP_PKEY_free( pub );
            EVP_PKEY_CTX_free( ctx );
            return std::unexpected( "EVP_PKEY_derive_set_peer failed" );
        }
        std::size_t secret_len = 0;
        if ( EVP_PKEY_derive( ctx, nullptr, &secret_len ) <= 0 ) {
            EVP_PKEY_free( priv );
            EVP_PKEY_free( pub );
            EVP_PKEY_CTX_free( ctx );
            return std::unexpected( "EVP_KEY_derive length failed" );
        } 
        std::vector<uint8_t> secret( secret_len );
        if ( EVP_PKEY_derive( ctx, secret.data(), &secret_len ) <= 0 ) {
            EVP_PKEY_free( priv );
            EVP_PKEY_free( pub );
            EVP_PKEY_CTX_free( ctx );
            return std::unexpected( "EVP_KEY_derive failed" );
        }
        EVP_PKEY_free( priv );
        EVP_PKEY_free( pub );
        EVP_PKEY_CTX_free( ctx );
        return secret;
    }

    // =============================
    //  Generate SECP256R1 Key Pair
    // =============================

    std::expected<secp256r1_key_pair,std::string> generate_secp256r1_key_pair() {
        secp256r1_key_pair key_pair;
        EC_KEY* ec = EC_KEY_new_by_curve_name( NID_X9_62_prime256v1 );
        if ( !ec ) {
            return std::unexpected( "Failed to Create EC_KEY" );
        }
        if ( !EC_KEY_generate_key( ec ) ) {
            EC_KEY_free( ec );
            return std::unexpected( "EX_KEY_generate_key failed" );
        }
        const BIGNUM* priv_bn = EC_KEY_get0_private_key( ec );
        if ( !priv_bn ) {
            EC_KEY_free( ec );
            return std::unexpected( "Failed to Get Private Key");
        }
        BN_bn2binpad( priv_bn, key_pair.private_key.data(), key_pair.private_key.size() );

        const EC_POINT* pub_pt = EC_KEY_get0_public_key( ec );
        const EC_GROUP* group = EC_KEY_get0_group( ec );
        std::size_t pub_len = 65;
        if ( EC_POINT_point2oct(group, pub_pt, POINT_CONVERSION_UNCOMPRESSED,
                                key_pair.public_key.data(), pub_len, nullptr ) != 65 ) {
            EC_KEY_free( ec );
            return std::unexpected( "Failed to Extract Public Key" );
        }
        EC_KEY_free( ec );
        return key_pair;
    }

    // ================================
    //  Derive SECP256R1 Shared Secret
    // ================================

    std::expected<std::vector<uint8_t>,std::string>
    derive_secp256r1_shared_secret( const std::array<uint8_t,32>& private_key,
                                    const std::array<uint8_t,65>& peer_public_key) {
        EVP_PKEY_CTX* ctx = nullptr;
        EVP_PKEY* priv = nullptr;
        EVP_PKEY* pub = nullptr;

        EC_KEY* ec_priv = EC_KEY_new_by_curve_name( NID_X9_62_prime256v1 );
        if ( !ec_priv ) { 
            return std::unexpected( "Failed to create EC_KEY for private key" );
        }
        BIGNUM* priv_bn = BN_bin2bn( private_key.data(), private_key.size(), nullptr );
        if ( !priv_bn ) {
            EC_KEY_free( ec_priv );
            return std::unexpected( "Failed to convert private key to BIGNUM" );
        }
        if ( !EC_KEY_set_private_key( ec_priv, priv_bn ) ) {
            BN_free( priv_bn );
            EC_KEY_free( ec_priv );
            return std::unexpected( "Failed to set private key" );
        }
        BN_free( priv_bn );
        EC_KEY* ec_pub = EC_KEY_new_by_curve_name( NID_X9_62_prime256v1 );
        if ( !ec_pub ) {
            EC_KEY_free( ec_priv );
            return std::unexpected( "Failed to create EC_KEY for peer public key" );
        }

        const EC_GROUP* group = EC_KEY_get0_group( ec_pub );
        EC_POINT* pub_point = EC_POINT_new( group );
        if ( !pub_point ) {
            EC_KEY_free( ec_priv );
            EC_KEY_free( ec_pub );
            return std::unexpected( "Failed to create EC_POINT" );
        }

        if (!EC_POINT_oct2point( group, pub_point, peer_public_key.data(), peer_public_key.size(), nullptr ) ) {
            EC_POINT_free( pub_point );
            EC_KEY_free( ec_priv );
            EC_KEY_free( ec_pub );
            return std::unexpected( "Failed to decode peer public key" );
        }

        if (!EC_KEY_set_public_key( ec_pub, pub_point ) ) {
            EC_POINT_free( pub_point );
            EC_KEY_free( ec_priv );
            EC_KEY_free( ec_pub );
            return std::unexpected( "Failed to set peer public key" );
        }
        EC_POINT_free( pub_point );

        priv = EVP_PKEY_new();
        pub = EVP_PKEY_new();
        if ( !priv || !pub ) {
            EC_KEY_free( ec_priv );
            EC_KEY_free( ec_pub );
            if ( priv ) { 
                EVP_PKEY_free( priv );
            }
            if ( pub ) { 
                EVP_PKEY_free(pub);
            }
            return std::unexpected( "Failed to allocate EVP_PKEYs" );
        }
        EVP_PKEY_assign_EC_KEY( priv, ec_priv );
        EVP_PKEY_assign_EC_KEY( pub, ec_pub );
        ctx = EVP_PKEY_CTX_new( priv, nullptr );
        if ( !ctx ) {
            EVP_PKEY_free( priv );
            EVP_PKEY_free( pub );
            return std::unexpected( "Failed to create PKEY_CTX" );
        }
        if ( EVP_PKEY_derive_init( ctx ) <= 0 ) {
            EVP_PKEY_free( priv );
            EVP_PKEY_free( pub );
            EVP_PKEY_CTX_free( ctx );
            return std::unexpected( "EVP_PKEY_derive_init failed" );
        }
        if ( EVP_PKEY_derive_set_peer( ctx, pub ) <= 0 ) {
            EVP_PKEY_free( priv );
            EVP_PKEY_free( pub );
            EVP_PKEY_CTX_free( ctx );
            return std::unexpected( "EVP_PKEY_derive_set_peer failed" );
        }

        std::size_t secret_len = 0;
        if ( EVP_PKEY_derive( ctx, nullptr, &secret_len ) <= 0 ) {
            EVP_PKEY_free( priv );
            EVP_PKEY_free( pub );
            EVP_PKEY_CTX_free( ctx );
            return std::unexpected( "EVP_PKEY_derive length failed" );
        }

        std::vector<uint8_t> secret( secret_len );
        if (EVP_PKEY_derive( ctx, secret.data(), &secret_len ) <= 0 ) {
            EVP_PKEY_free( priv );
            EVP_PKEY_free( pub );
            EVP_PKEY_CTX_free( ctx );
            return std::unexpected( "EVP_PKEY_derive failed" );
        }

        EVP_PKEY_free( priv );
        EVP_PKEY_free( pub );
        EVP_PKEY_CTX_free( ctx );
        return secret;
    }

} // namespace ntk

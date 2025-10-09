#include <crypto.hpp>

namespace ntk {

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

} // namespace ntk

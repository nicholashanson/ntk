#include <gtest/gtest.h>

#include <crypto.hpp>

TEST( UnitTest, GenerateSecp256R1KeyPair ) {
    auto first_key_pair_result = ntk::generate_secp256r1_key_pair();
    ASSERT_TRUE( first_key_pair_result ) << first_key_pair_result.error() << std::endl;
    auto& [ client_private_key, client_public_key ] = first_key_pair_result.value();
    auto second_key_pair_result = ntk::generate_secp256r1_key_pair();
    ASSERT_TRUE( second_key_pair_result ) << second_key_pair_result.error() << std::endl;
    auto& [ server_private_key, server_public_key ] = second_key_pair_result.value();
    auto client_secret_result = ntk::derive_secp256r1_shared_secret( client_private_key, server_public_key );
    ASSERT_TRUE( client_secret_result ) << client_secret_result.error() << std::endl;
    auto& client_secret = client_secret_result.value();
    auto server_secret_result = ntk::derive_secp256r1_shared_secret( server_private_key, client_public_key );
    ASSERT_TRUE( server_secret_result ) << server_secret_result.error() << std::endl;
    auto& server_secret = client_secret_result.value();
    EXPECT_EQ( client_secret, server_secret );
}
#include <gtest/gtest.h>

#include <tls.hpp>

/*
TEST( UnitTest, DiffieHelmanRoundTrip ) {
    auto [ client_private_key, client_public_key ] = ntk::generate_key_pair();
    auto [ server_private_key, server_public_key ] = ntk::generate_key_pair();
    auto client_secret = ntk::derive_shared_secret( client_private_key, server_public_key );
    auto server_secret = ntk::derive_shared_secret( server_private_key, client_private_key );
    EXPECT_EQ( client_secret, server_secret );
}
*/
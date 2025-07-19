#include <gtest/gtest.h>

#include <cstdint>
#include <span>

#include <tls.hpp>
#include <io.hpp>

#include <test_constants.hpp>
#include <test_tls_handshake_packets.hpp>

TEST( UnitTest, GetTlsSecrets ) {
    auto session_keys = ntk::get_tls_secrets( "tls_session_keys.log" );
    ASSERT_EQ( session_keys.size(), 2 );
}
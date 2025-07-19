#include <gtest/gtest.h>

#include <span>
#include <cstdint>

#include <tcp.hpp>
#include <io.hpp>

#include <test_constants.hpp>

TEST( UnitTest, GetLineNumbers ) {
    auto tcp_line_numbers = ntk::get_line_numbers( test::packet_data_files[ "tls_handshake" ], ntk::is_tcp_v );
    ASSERT_EQ( tcp_line_numbers.size(), 19 );
}


#include <gtest/gtest.h>

#include <cstdint>
#include <span>

#include <tcp.hpp>
#include <io.hpp>

#include <test_constants.hpp>

TEST( UnitTest, GetLineNumbers ) {
    auto tcp_line_numbers = ntk::get_line_numbers( test::packet_data_files[ "tls_handshake" ], [] ( const auto& packet ) {
                                                                                                   auto result = ntk::is_tcp( packet );
                                                                                                   return result.has_value() && result.value(); 
                                                                                               } );
    ASSERT_EQ( tcp_line_numbers.size(), 19 );
}


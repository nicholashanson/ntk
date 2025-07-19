#include <gtest/gtest.h>

#include <cstdint>

#include <tls.hpp>

#include <test_constants.hpp>
#include <test_tls_handshake_packets.hpp>

TEST( IntegrationTest, ClientHelloEquivalentFromEthernetAndRecord ) {
    auto client_hello_from_ethernet = ntk::get_client_hello_from_ethernet_frame( test_constants::tls_client_hello_packet );
    
    auto result = ntk::get_tls_record_from_ethernet( test_constants::tls_client_hello_packet );
    ntk::tls_record client_hello_record;

    if ( result.has_value() ) {
        client_hello_record = result.value();
    } else {
        std::cerr << result.error() << '\n';
    }

    auto client_hello_from_record = ntk::get_client_hello( client_hello_record );
    ASSERT_EQ( client_hello_from_ethernet, client_hello_from_record );
}
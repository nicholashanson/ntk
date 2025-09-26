#include <gtest/gtest.h>

#include <cstdint>

#include <tls.hpp>

#include <test_constants.hpp>
#include <test_tls_handshake_packets.hpp>

TEST( IntegrationTest, GetClientHelloFromEthernetFrameGetTlsRecordFromEthernet ) {
    auto client_hello_from_ethernet_result = ntk::get_client_hello_from_ethernet_frame( test_constants::tls_client_hello_packet );
    ASSERT_TRUE( client_hello_from_ethernet_result ) << client_hello_from_ethernet_result.error() << std::endl;
    auto result = ntk::get_tls_record_from_ethernet( test_constants::tls_client_hello_packet );
    ASSERT_TRUE( result ) << result.error() << std::endl;
    auto client_hello_record = result.value();
    auto client_hello_from_record_result = ntk::get_client_hello( client_hello_record );
    ASSERT_TRUE( client_hello_from_record_result ) << client_hello_from_record_result.error() << std::endl;
    ASSERT_EQ( client_hello_from_ethernet_result.value(), client_hello_from_record_result.value() );
}
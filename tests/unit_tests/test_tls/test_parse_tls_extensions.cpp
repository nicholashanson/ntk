#include <gtest/gtest.h>

#include <io.hpp>
#include <x_509.hpp>

#include <test_constants.hpp>

TEST( UnitTest, ParseTlsExtensions ) {
    auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "segment_capture" ] );
    ASSERT_FALSE( packet_data.empty() );
    auto& client_hello_packet = packet_data[ 10 ];
    auto client_hello_result = ntk::get_client_hello_from_ethernet_frame( client_hello_packet );
    ASSERT_TRUE( client_hello_result ) << client_hello_result.error() << std::endl;
    auto& client_hello = client_hello_result.value();
    auto parse_result = ntk::parse_tls_extensions( client_hello.extensions );
    ASSERT_TRUE( parse_result ) << parse_result.error() << std::endl;
    auto& extensions = parse_result.value();
    EXPECT_EQ( extensions[ 0 ].value.size(), 0 );
    EXPECT_EQ( extensions[ 1 ].value.size(), 1 );
}

TEST( UnitTest, ParseTlsExtensions_GenerateClientHello ) {
    ntk::generate_default_client_config();
    auto config = ntk::load_client_config();
    auto generate_result = ntk::generate_client_hello( config );
    ASSERT_TRUE( generate_result ) << generate_result.error() << std::endl;
    auto& generated_client_hello = generate_result.value();
    auto parse_result = ntk::parse_client_hello( generated_client_hello.client_hello );
    ASSERT_TRUE( parse_result ) << parse_result.error() << std::endl;
    auto extensions_result = ntk::parse_tls_extensions( parse_result.value().extensions );
    ASSERT_TRUE( extensions_result ) << extensions_result.error() << std::endl;
}
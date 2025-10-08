#include <gtest/gtest.h>

#include <http.hpp>

#include <test_constants.hpp>

TEST( UnitTest, GetHttpType_Request ) {
    auto payload_result = ntk::get_tcp_payload( test::http_get_packet );
    ASSERT_TRUE( payload_result ) << payload_result.error() << std::endl;
    ASSERT_TRUE( payload_result.value() ) << "TCP Payload is empty" << std::endl;
    auto& payload = *payload_result.value(); 
    auto type_result = ntk::get_http_type( payload );
    ASSERT_TRUE( type_result ) << "TCP Payload is too short to be a HTTP Message" << std::endl; 
    ASSERT_EQ( type_result.value(), ntk::http_type::request );
}

TEST( UnitTest, GetHttpType_Response ) {
    auto payload_result = ntk::get_tcp_payload( test::http_response_packet );
    ASSERT_TRUE( payload_result ) << payload_result.error() << std::endl;
    ASSERT_TRUE( payload_result.value() ) << "TCP Payload is empty" << std::endl;
    auto& payload = *payload_result.value(); 
    auto type_result = ntk::get_http_type( payload );
    ASSERT_TRUE( type_result ) << "TCP Payload is too short to be a HTTP Message" << std::endl; 
    ASSERT_EQ( type_result.value(), ntk::http_type::response );
}

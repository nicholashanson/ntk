#include <gtest/gtest.h>

#include <cstdint>
#include <span>

#include <tls.hpp>
#include <io.hpp>

#include <test_constants.hpp>

TEST( UnitTest, SplitTlsRecords ) {
    const unsigned char first_packet[] = {
        // record 1
        0x16, 0x03, 0x03, 0x00, 0x01, 0xaa,     
        // record 2
        0x17, 0x03, 0x03, 0x00, 0x01, 0xbb,      
        // record 3: first 7 bytes
        0x16, 0x03, 0x03, 0x00, 0x04, 0xcc, 0xdd  
    };
    const unsigned char second_packet[] = {
        // record 3: last 2 bytes
        0xee, 0xff
    };
    auto split_result = ntk::split_tls_records( std::span( first_packet, sizeof( first_packet ) ) );
    ASSERT_TRUE( split_result ) << split_result.error() << std::endl;
    auto [ first_records, first_offset ] = split_result.value();
    EXPECT_EQ( first_records.size(), 2 );
    EXPECT_EQ( first_offset, 12 );
    std::vector<uint8_t> remainder( first_packet + first_offset, first_packet + sizeof( first_packet ) );
    remainder.insert( remainder.end(), second_packet, second_packet + sizeof( second_packet ) );
    auto [ second_records, second_offset ] = *ntk::split_tls_records( remainder );
    EXPECT_EQ( second_records.size(), 1 );
    EXPECT_EQ( second_offset, 9 );
}

TEST( UnitTest, SplitTlsRecords_TlsHandshake ) {
    auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "tls_handshake" ] );
    auto merged_stream = ntk::get_merged_tcp_stream( packet_data );
    auto first_packet_pos = merged_stream.begin();
    auto first_packet = first_packet_pos->second;
    auto second_packet_pos = std::next( first_packet_pos );
    auto second_packet = second_packet_pos->second;
    auto first_split_result = ntk::split_tls_records( std::span( first_packet.data(), first_packet.size() ) );
    ASSERT_TRUE( first_split_result ) << first_split_result.error() << std::endl;
    auto [ first_records, first_offset ] = first_split_result.value();
    EXPECT_EQ( first_records.size(), 2 );
    std::vector<uint8_t> remainder( first_packet.data() + first_offset, first_packet.data() + first_packet.size() );
    remainder.insert( remainder.end(), second_packet.data(), second_packet.data() + second_packet.size() );
    auto second_split_result = ntk::split_tls_records( remainder );
    ASSERT_TRUE( second_split_result ) << second_split_result.error() << std::endl;
    auto [ second_records, second_offset ] = second_split_result.value();
    EXPECT_EQ( second_records.size(), 1 );
    EXPECT_EQ( second_offset, second_records[ 0 ].payload.size() + 5 );
    EXPECT_EQ( second_offset, remainder.size() );
}

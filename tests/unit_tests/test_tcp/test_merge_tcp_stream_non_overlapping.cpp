#include <gtest/gtest.h>

#include <tcp.hpp>
#include <io.hpp>

#include <test_constants.hpp>

TEST( UnitTest, MergeTcpStreamNonOverlapping ) {
    ntk::tcp_stream overlapping_stream = {
        { 1000, { 'A', 'B', 'C', 'D' } },    
        { 1004, { 'E', 'F', 'G' } },          
        { 1002, { 'C', 'D', 'E', 'F' } },     
        { 1010, { 'H', 'I' } },              
        { 1003, { 'D', 'E', 'F' } }            
    };
    ntk::tcp_stream actual_merged_stream = ntk::merge_tcp_stream_non_overlapping( overlapping_stream );
    ntk::tcp_stream expected_merged_stream = {
        { 1000, { 'A', 'B', 'C', 'D' } },
        { 1004, { 'E', 'F' } },
        { 1006, { 'G' } },
        { 1010, { 'H', 'I' } }
    };
    ASSERT_EQ( actual_merged_stream, expected_merged_stream );
}

TEST( UnitTest, MergeTcpStreamNonOverlapping_Lena ) {
    auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "lena" ] );
    auto raw_stream = ntk::get_raw_tcp_stream( packet_data );
    auto tcp_stream = ntk::get_tcp_stream( raw_stream );
    auto merged_tcp_stream = ntk::merge_tcp_stream_non_overlapping( tcp_stream );
    ASSERT_TRUE( ntk::is_non_overlapping_stream( merged_tcp_stream ) );
}
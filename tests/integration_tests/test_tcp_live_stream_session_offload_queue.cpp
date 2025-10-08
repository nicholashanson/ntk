#include <gtest/gtest.h>

#include <tcp.hpp>
#include <io.hpp>
#include <spmc_queue.hpp>

#include <test_constants.hpp>

TEST( UnitTest, TcpLiveStreamSession_OffloadQueue ) {
    auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "checkerboard" ] );
    ASSERT_FALSE( packet_data.empty() );
    ntk::spmc_transfer_queue<ntk::tcp_live_stream> offload_queue;
    ntk::tcp_live_stream_session live_stream_session( &offload_queue ); 
    ASSERT_TRUE( offload_queue.empty() ) ;
    for ( auto& packet : packet_data ) {
        live_stream_session.feed_packet( packet );
    }
    ASSERT_TRUE( live_stream_session.number_of_completed_transfers() == 0 );
    ASSERT_FALSE( offload_queue.empty() );
}
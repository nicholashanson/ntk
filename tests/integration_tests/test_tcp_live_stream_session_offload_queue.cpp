#include <gtest/gtest.h>

#include <span>
#include <cstdint>

#include <tcp.hpp>
#include <io.hpp>
#include <spmc_queue.hpp>
#include <test_constants.hpp>

TEST( UnitTest, TcpLiveStreamSession_OffloadQueue ) {
    ntk::spmc_transfer_queue<ntk::tcp_live_stream> offload_queue;
    ntk::tcp_live_stream_session live_stream_session( &offload_queue ); 
    auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "checkerboard" ] );
    ASSERT_TRUE( offload_queue.empty() ) ;

    for ( auto& packet : packet_data ) {
        live_stream_session.feed( packet );
    }

    ASSERT_TRUE( live_stream_session.number_of_completed_transfers() == 0 );
    ASSERT_FALSE( offload_queue.empty() );
}
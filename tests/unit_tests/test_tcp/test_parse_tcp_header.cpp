#include <gtest/gtest.h>

#include <vector>
#include <iomanip>

#include <ipv4.hpp>
#include <tcp.hpp>

#include <test_tcp_handshake_packets.hpp>

TEST( UnitTest, ParseTcpHeader_SYN ) {
    ntk::tcp_header actual_header = ntk::parse_tcp_header( test_constants::tcp_syn_packet_tcp_header );
    ntk::tcp_header expected_header = {
        .source_port = 44056,                    
        .destination_port = 3000,                
        .sequence_number = 0xb920c9b3,           
        .acknowledgment_number = 0,               
        .data_offset = 10,                                          
        .window_size = 65535,                                            
        .checksum = 5998,                                                
        .urgent_pointer = 0,                                             
        .options = {                                                        
            { ntk::option_type::MSS, { 0x05, 0xb4 } },                            
            { ntk::option_type::SACK_PERMITTED, {} },                                              
            { ntk::option_type::TIMESTAMP, { 0x02, 0x0d, 0x72, 0x64, 0x00, 0x00, 0x00, 0x00 } },   
            { ntk::option_type::NOP, {} },                                                 
            { ntk::option_type::WINDOW_SCALE, { 0x09 } }                                   
        }
    };
    ASSERT_EQ( expected_header, actual_header );
}

TEST( UnitTest, ParseTcpHeader_SYNACK ) {
    ntk::tcp_header actual_header = ntk::parse_tcp_header( test_constants::tcp_synack_packet_tcp_header );
    ntk::tcp_header expected_header = {
        .source_port = 3000,                                               
        .destination_port = 44056,                                        
        .sequence_number = 0xd3c1ea09,           
        .acknowledgment_number = 0xb920c9b4,     
        .data_offset = 10,                   
        .window_size = 0xfe88,                   
        .checksum = 0x81a8,                      
        .urgent_pointer = 0x0000,                
        .options = {
            { ntk::option_type::MSS, { 0x05, 0xb4 } },                                         
            { ntk::option_type::SACK_PERMITTED, {} },                                                 
            { ntk::option_type::TIMESTAMP, { 0x58, 0x64, 0xbc, 0x69, 0x02, 0x0d, 0x72, 0x64 } },      
            { ntk::option_type::NOP, {} },                                                   
            { ntk::option_type::WINDOW_SCALE, { 0x07 } }                                       
        }
    };
    ASSERT_EQ( expected_header, actual_header );
}

TEST( UnitTest, ParseTcpHeader_ACK ) {
    ntk::tcp_header actual_header = ntk::parse_tcp_header( test_constants::tcp_ack_packet_tcp_header );
    ntk::tcp_header expected_header = {
        .source_port = 44056,                                    
        .destination_port = 3000,                                     
        .sequence_number = 0xb920c9b4,             
        .acknowledgment_number = 0xd3c1ea0a,       
        .data_offset = 8,                                             
        .window_size = 0x0080,                     
        .checksum = 0x72de,                        
        .urgent_pointer = 0x0000,                  
        .options = {
            { ntk::option_type::NOP, {} },                                                  
            { ntk::option_type::NOP, {} },                                                 
            { ntk::option_type::TIMESTAMP, { 0x02, 0x0d, 0x72, 0x97, 0x58, 0x64, 0xbc, 0x69 } }   
        }
    };
    ASSERT_EQ( expected_header, actual_header );
}
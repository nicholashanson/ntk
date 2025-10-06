#ifndef IO_HPP
#define IO_HPP

#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>
#include <string>
#include <unordered_set>
#include <cstdint>
#include <iomanip>

#include <constants.hpp>
#include <tcp.hpp>
#include <ipv4.hpp>
#include <tls.hpp>
#include <http.hpp>
#include <x_509.hpp>

namespace ntk {

    // =================
    //  Parese Hex Line
    // =================

    std::vector<uint8_t> parse_hex_line( const std::string& line );

    template<typename Key,typename Value>
    bool is_one_to_one_mapping( const std::map<Key, Value>& m ) {
        std::unordered_set<Value> seen_values;
        for ( const auto& [ key, value ] : m ) {
            if ( !seen_values.insert( value ).second ) {
                return false;
            }
        }
        return true;
    }

    // ================
    //  Four To String
    // ================

    std::string four_to_string( const four_tuple& four );

    // ==============
    //  Print Vector
    // ==============

    void print_vector( std::span<const uint8_t> data );

    // ====================
    //  Print Packet Array
    // ====================

    void print_packet_array( const unsigned char* packet_data, const std::size_t packet_len );

    // =============
    //  Print Array
    // =============

    template<size_t n>
    void print_array( const std::array<uint8_t,n>& data ) {
        for ( auto byte : data ) {
            std::cout << std::hex << std::setw( 2 ) << std::setfill( '0' ) << static_cast<int>( byte ) << " ";
        }
        std::cout << std::dec << std::endl;
    }

    // ========================
    //  Read Packets From File
    // ========================

    session read_packets_from_file( const std::string& packet_data_file );

    // ==================
    //  Get Line Numbers
    // ==================

    template<typename Filter>
    std::vector<int> get_line_numbers( const std::string& filename, Filter&& filter ) {
        std::ifstream file( filename );
        std::vector<int> line_numbers;

        if ( !file.is_open() ) {
            std::cerr << "Failed to open file: " << filename << '\n';
            return line_numbers;
        }

        std::string line;
        int line_number = 0;

        while ( std::getline( file, line ) ) {
            line_number++;
            std::vector<uint8_t> packet = parse_hex_line( line );
            if ( filter( packet ) ) {
                line_numbers.push_back( line_number );
            }
        }
        return line_numbers;
    }

    // =============================
    //  Get Packets By Line Numbers
    // =============================

    std::vector<std::vector<uint8_t>> get_packets_by_line_numbers( const std::string& filename,
                                                                   const std::vector<int>& line_numbers );

    // =============
    //  File Output
    // =============

    void output_stream_to_file( const std::string& filename, const tcp_live_stream& live_stream );

    void output_packet( const std::vector<uint8_t> packet, std::ofstream& ofs );

    void write_payload_to_file( const std::vector<uint8_t>& payload, const std::string& filename );

    // ===========
    //  Print TCP
    // ===========

    void print_four( const four_tuple& four, std::ostream& os = std::cout );

    void print_tcp_header( const tcp_header& header, std::ostream& os = std::cout ); 

    void print_tcp_header( std::span<const uint8_t> packet, std::ostream& os = std::cout );

    void print_tcp_stream_info( const std::map<uint32_t, std::vector<uint8_t>>& stream );

    void print_tcp_options( const tcp_header& header );

    // ===========
    //  Print TLS
    // ===========

    void print_tls_record( const tls_record& record );

    void print_tls_secrets( const secrets& keys );

    void print_client_hello( const client_hello& c_hello, std::ostream& os = std::cout );

    void print_server_hello( const server_hello& s_hello, std::ostream& os = std::cout );

    // ============
    //  Print HTTP
    // ============

    void print_http_request( const http_request& request, std::ostream& os = std::cout ); 

    void print_http_request( std::span<const uint8_t> payload, std::ostream& os = std::cout );

    void print_http_response( const http_response& response, std::ostream& os = std::cout );

    void print_http_response( std::span<const uint8_t> payload, std::ostream& os = std::cout );

    void print_tcp_termination( const tcp_termination& termination ); 

    // =======================
    //  Print Tbs Certificate
    // =======================

    void print_tbs_certificate( std::span<const uint8_t> certificate );

    void print_tbs_extension( const extension& ext );

    void print_tbs_extensions( std::span<extension> extensions );

} // namespace ntk

#endif
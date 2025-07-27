#ifndef HTTP_HPP
#define HTTP_HPP

#include <algorithm>

#include <cstdint>
#include <cstring>
#include <unordered_map>
#include <string>
#include <vector>
#include <sstream>

#include <constants.hpp>
#include <tcp.hpp>

namespace ntk {

    // TODO: check http rules on whitespace in headers
    std::string trim( const std::string& str );

    // ==============================
    //           HTTP Type
    // ==============================

    enum class http_type {
        REQUEST,
        RESPONSE,
        DATA
    };

    // ==============================
    //          Predicates
    // ==============================

    bool is_http( const std::vector<uint8_t>& maybe_http_payload );

    bool ends_with_zero_chunk( const tcp_stream& stream );

    // ==============================
    //         HTTP Headers
    // ==============================

    using http_headers = std::unordered_map<std::string,std::string>;

    http_headers parse_http_headers( const std::vector<uint8_t>& header_bytes );

    http_headers get_http_headers_from_payload( const std::vector<uint8_t>& http_payload_bytes );

    http_type get_http_type( const std::vector<uint8_t>& http_payload );

    // ==============================
    //        HTTP Request
    // ==============================

    struct http_request_line {
        std::string method_token;
        std::string path;
        std::string http_version;
    };

    struct http_request {
        http_request_line request_line;
        http_headers headers;
    };

    http_request_line parse_http_request_line( const std::vector<uint8_t>& request_line_bytes );

    http_request get_http_request( const std::vector<uint8_t>& http_payload );

    std::vector<uint8_t> get_first_http_respone( const session& packet_data );

    // ==============================
    //        HTTP Response
    // ==============================

    struct http_response_status_line {
        std::string http_version;
        int status_code;
        std::string reason_phrase;
    };

    struct http_response {
        http_response_status_line status_line;
        http_headers headers;
        std::vector<uint8_t> body;
    };

    struct incomplete_http_response {
        std::size_t content_length;
        std::vector<uint8_t> body;

        bool http_response_complete() {
            return content_length == body.size();
        }
    };

    http_response_status_line parse_http_status_line( const std::vector<uint8_t>& status_line_bytes );

    http_response get_http_response( const std::vector<uint8_t>& http_payload );

    std::vector<uint8_t> get_http_response_data( const tcp_stream& stream );

    // ==============================
    //       Split HTTP Payload
    // ==============================

    std::tuple<std::vector<uint8_t>, std::vector<uint8_t>, std::vector<uint8_t>>
    split_http_payload( const std::vector<uint8_t>& payload );

    bool contains_http_header( const http_headers& headers, const std::string& header_name );
   
    // ==============================
    //        Chunk Decoding
    // ==============================

    std::vector<uint8_t> decode_single_chunk( const std::vector<uint8_t>& chunked_body );

    std::vector<uint8_t> decode_chunked_http_body( const std::vector<uint8_t>& chunked_body );

} // namespace ntk

#endif
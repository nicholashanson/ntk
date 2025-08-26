#ifndef HTTP_HPP
#define HTTP_HPP

#include <algorithm>

#include <cstdint>
#include <cstring>
#include <unordered_map>
#include <string>
#include <vector>
#include <sstream>
#include <fstream>

#include <constants.hpp>
#include <tcp.hpp>

namespace ntk {

    enum class http_parse_error {
        MISSING_START_LINE,
        MISSING_HEADERS,
        UNRECOGNIZED_MIME_TYPE
    };

    enum class mime_type : uint8_t {
        VIDEO_MP2T,
        APPLICATION_VND_APPLE_MPEGURL,
        TEXT_PLAIN
    };

    enum class file_extension : uint8_t {
        M3U8,
        TS
    };

    struct split_http_message {
        std::vector<uint8_t> start_line;
        std::vector<uint8_t> headers;
        std::vector<uint8_t> body;
    };

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

    bool is_http_request_packet( std::span<const unsigned char> packet );

    bool is_http_request( const std::vector<uint8_t>& tcp_payload );

    bool is_http_response_packet( std::span<const unsigned char> packet );

    bool is_http_response( const std::vector<uint8_t>& tcp_payload );

    bool ends_with_zero_chunk( const tcp_stream& stream );

    // ==============================
    //         HTTP Headers
    // ==============================

    using http_headers = std::unordered_map<std::string,std::string>;

    http_headers parse_http_headers( const std::vector<uint8_t>& header_bytes );

    std::expected<http_headers,http_parse_error> get_http_headers_from_payload( std::span<const unsigned char> http_payload_bytes );

    http_type get_http_type( const std::vector<uint8_t>& http_payload );

    std::expected<mime_type,http_parse_error> get_mime_type_from_ethernet( std::span<const unsigned char> ethernet_frame );

    std::optional<mime_type> string_to_mime_type( const std::string& mime_type_string );

    // ==============================
    //        HTTP Request
    // ==============================

    // TODO: change "path" to "request_target"
    struct http_request_line {
        std::string method_token;
        std::string request_target;
        std::string http_version;
    };

    struct http_request {
        http_request_line request_line;
        http_headers headers;
    };

    http_request_line parse_http_request_line( const std::vector<uint8_t>& request_line_bytes );

    std::expected<http_request,http_parse_error> get_http_request( std::span<const unsigned char> http_payload );

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

    std::expected<http_response,http_parse_error> get_http_response( const std::vector<uint8_t>& http_payload );

    std::expected<std::vector<uint8_t>,http_parse_error> get_http_response_data( const tcp_stream& stream );

    // ==============================
    //       Split HTTP Payload
    // ==============================

    std::expected<split_http_message,http_parse_error> split_http_payload( std::span<const unsigned char> payload );

    bool contains_http_header( const http_headers& headers, const std::string& header_name );
   
    // ==============================
    //        Chunk Decoding
    // ==============================

    std::vector<uint8_t> decode_single_chunk( const std::vector<uint8_t>& chunked_body );

    std::vector<uint8_t> decode_chunked_http_body( const std::vector<uint8_t>& chunked_body );

    std::optional<file_extension> extract_file_extension( const std::string& path );

    std::string get_path( const std::string& request_target );

    std::optional<file_extension> string_to_file_extension( const std::string& file_extension_string );

    std::optional<std::string> file_extension_to_string( file_extension extension );

    template<file_extension F>
    bool is_request_for( const http_request& request ) {
        auto path = get_path( request.request_line.request_target );
        auto file_extension = extract_file_extension( path );
        if ( !file_extension ) {
            return false;
        }
        return file_extension == F; 
    }

    std::string write_to_file( const std::vector<uint8_t>& data, file_extension extension );

} // namespace ntk

#endif
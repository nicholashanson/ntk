#include <http.hpp>

namespace ntk {

    // ==============================
    //             Trim 
    // ==============================

    std::string trim( const std::string& str ) {
        size_t start = str.find_first_not_of(" \t\r\n" );
        size_t end = str.find_last_not_of(" \t\r\n" );
        return ( start == std::string::npos || end == std::string::npos )
            ? ""
            : str.substr( start, end - start + 1 );
    }

    bool ends_with_zero_chunk( const tcp_stream& stream ) {
        const auto& [ seq, data ] = *stream.rbegin();
        std::vector<uint8_t> zero_chunk_pattern = { '\r', '\n', '\r', '\n' };
        return std::equal( zero_chunk_pattern.rbegin(), zero_chunk_pattern.rend(), data.rbegin() );
    };

    // ==============================
    //           Is HTTP
    // ==============================

    bool is_http( const std::vector<uint8_t>& maybe_http_payload ) {
        std::string first_five( maybe_http_payload.begin(), maybe_http_payload.begin() + 5 );
        if ( first_five.compare( 0, 5, "HTTP/" ) == 0 || first_five.compare( 0, 3, "GET" ) == 0 ) {
            return true;
        }
        return false;
    }

    // ==============================
    //        Is HTTP Request
    // ==============================

    bool is_http_request_packet( std::span<const unsigned char> packet ) {
        auto payload = get_tcp_payload( packet );
        return is_http_request( payload );
    }

    bool is_http_request( const std::vector<uint8_t>& tcp_payload ) {
        return get_http_type( tcp_payload ) == http_type::REQUEST;
    }

    // ==============================
    //        Is HTTP Response
    // ==============================

    bool is_http_response_packet( std::span<const unsigned char> packet ) {
        auto payload = get_tcp_payload( packet );
        return is_http_response( payload );
    }

    bool is_http_response( const std::vector<uint8_t>& tcp_payload ) {
        return get_http_type( tcp_payload ) == http_type::RESPONSE; 
    }

    // ==============================
    //         Get HTTP Type
    // ==============================

    http_type get_http_type( const std::vector<uint8_t>& http_payload ) {
        std::string first_five( http_payload.begin(), http_payload.begin() + 5 );

        if ( first_five.compare( 0, 5, "HTTP/" ) == 0 ) {
            return http_type::RESPONSE; 
        } else if ( first_five.compare( 0, 3, "GET" ) == 0 ) {
            return http_type::REQUEST;
        } else {
            return http_type::DATA;
        }
    }

    std::expected<split_http_message,http_parse_error> split_http_payload( std::span<const unsigned char> payload ) {
        auto begin = payload.begin();
        auto end = payload.end();
        auto start_line_end = std::search( begin, end, "\r\n", "\r\n" + 2 );
        if ( start_line_end == end ) {
            return std::unexpected( http_parse_error::MISSING_START_LINE );
        } 
        auto headers_start = start_line_end + 2; 
        auto headers_end = std::search( headers_start, end, "\r\n\r\n", "\r\n\r\n" + 4 );
        if ( headers_end == end ) {
            return std::unexpected( http_parse_error::MISSING_HEADERS );
        }
        auto body_start = headers_end + 4; 
        return split_http_message {
            { begin, start_line_end },
            { headers_start, headers_end },
            { body_start, end }
        };
    }

    http_request_line parse_http_request_line( const std::vector<uint8_t>& request_line_bytes ) {
        std::string request_line_string( request_line_bytes.begin(), request_line_bytes.end() );
        std::stringstream request_line_stream( request_line_string );
        http_request_line r_line;
        request_line_stream >> r_line.method_token >> r_line.request_target >> r_line.http_version;
        return r_line;
    }

    // ==============================
    //      Contains HTTP Header
    // ==============================

    bool contains_http_header( const http_headers& headers, const std::string& header_name  ) {
        return headers.contains( header_name );
    }  

    http_headers parse_http_headers(const std::vector<uint8_t>& header_bytes) {
        std::string headers_string( header_bytes.begin(), header_bytes.end() );
        http_headers headers;
        std::size_t pos = 0;

        while ( pos < headers_string.size() ) {
            std::size_t line_end = headers_string.find( "\r\n", pos );
            std::string line;

            if ( line_end == std::string::npos ) {
                line = headers_string.substr( pos );
                pos = headers_string.size();
            } else {
                line = headers_string.substr( pos, line_end - pos );
                pos = line_end + 2; 
            }

            std::size_t colon_pos = line.find( ':' );
            std::string key = trim( line.substr( 0, colon_pos ) );
            std::string value = trim( line.substr( colon_pos + 1 ) );
            headers[ key ] = value;
        }

        return headers;
    }

    std::expected<http_headers,http_parse_error> get_http_headers_from_payload( std::span<const unsigned char> http_payload_bytes ) {
        auto split_result = split_http_payload( http_payload_bytes );
        if ( !split_result ) {
            return std::unexpected( split_result.error() );
        }
        return parse_http_headers( split_result->headers );
    }

    http_response_status_line parse_http_status_line( const std::vector<uint8_t>& status_line_bytes ) {
        std::string line( status_line_bytes.begin(), status_line_bytes.end() );
        std::istringstream stream(line);
        
        http_response_status_line status_line;
        stream >> status_line.http_version;

        std::string status_code_string;
        stream >> status_code_string;
        status_line.status_code = std::stoi( status_code_string );

        std::string reason_phrase;
        std::getline( stream, reason_phrase );

        status_line.reason_phrase = trim( reason_phrase );
        return status_line;
    }

    std::vector<uint8_t> decode_single_chunk( const std::vector<uint8_t>& chunked_body ) {
        auto it = std::search( chunked_body.begin(), chunked_body.end(), "\r\n", "\r\n" + 2 );
        size_t chunk_size = std::stoul( std::string( chunked_body.begin(), it ), nullptr, 16 );
        auto data_start = it + 2;
        return std::vector<uint8_t>( data_start, data_start + chunk_size );
    }

    std::vector<uint8_t> decode_chunked_http_body( const std::vector<uint8_t>& chunked_body ) {
        std::vector<uint8_t> decoded;
        std::size_t pos = 0;

        while ( pos < chunked_body.size() ) {
            auto crlf = std::search( chunked_body.begin() + pos, chunked_body.end(), "\r\n", "\r\n" + 2 );
            if ( crlf == chunked_body.end() ) break;
            std::string chunk_size_str( chunked_body.begin() + pos, crlf );
            std::size_t chunk_size = std::stoul( chunk_size_str, nullptr, 16 );
            pos = crlf - chunked_body.begin() + 2;

            if ( chunk_size == 0 ) break;
            if ( pos + chunk_size > chunked_body.size() ) break;
            
            decoded.insert( decoded.end(), chunked_body.begin() + pos, chunked_body.begin() + pos + chunk_size );
            pos += chunk_size + 2;  
        }

        return decoded;
    }

    std::vector<uint8_t> get_first_http_respone( const session& packet_data ) {
        auto raw_tcp_stream = get_raw_tcp_stream( packet_data );
        auto tcp_stream = get_tcp_stream( raw_tcp_stream ); 
        std::cout << "hi" << std::endl;
        auto response = *std::find_if( tcp_stream.begin(), tcp_stream.end(), 
            []( const auto& pair ) { 
                auto& [ unused, http_payload ] = pair;
                return ntk::get_http_type( http_payload ) == ntk::http_type::RESPONSE;
            } 
        );

        return response.second;
    }   

    std::expected<std::vector<uint8_t>,http_parse_error> get_http_response_data( const tcp_stream& stream ) {
        auto response_pos = std::find_if( stream.begin(), stream.end(), 
            []( const auto& pair ) { 
                auto& [ unused, http_payload ] = pair;
                return ntk::get_http_type( http_payload ) == ntk::http_type::RESPONSE;
            } 
        );
        auto response = *response_pos;
        auto get_headers_result = get_http_headers_from_payload( response.second );
        if ( !get_headers_result ) {
            return std::unexpected( get_headers_result.error() );
        }
        auto http_headers = get_headers_result.value();
        auto split_result = split_http_payload( response.second );
        if ( !split_result ) {
            return std::unexpected( split_result.error() );
        }
        auto response_data = std::move( split_result->body );
        auto it = std::next( response_pos );

        while ( it != stream.end() ) {
            response_data.insert( response_data.end(),
                it->second.begin(), it->second.end() );
            ++it;
        }
        if ( contains_http_header( http_headers, "Content-Length" ) ) {
            return response_data;
        } else {
            return decode_chunked_http_body( response_data );
        }
    }

    std::expected<http_request,http_parse_error> get_http_request( std::span<const unsigned char> http_payload ) {
        auto split_result = split_http_payload( http_payload );
        if ( !split_result ) {
            return std::unexpected( split_result.error() );
        }
        http_request request;
        request.request_line = parse_http_request_line( split_result->start_line );
        request.headers = parse_http_headers( split_result->headers );
        return request;
    }

    std::expected<http_response,http_parse_error> get_http_response( const std::vector<uint8_t>& http_payload ) {
        http_response response;
        auto split_result = split_http_payload( http_payload );
        if ( !split_result ) {
            return std::unexpected( split_result.error() );
        }
        response.status_line = parse_http_status_line( split_result->start_line );
        response.headers = parse_http_headers( split_result->headers );
        response.body = split_result->body;
        return response;
    }

    std::optional<file_extension> extract_file_extension( const std::string& path ) {
        auto last_dot = path.rfind( '.' );
        if ( last_dot == std::string::npos ) return std::nullopt;
        return string_to_file_extension( path.substr( last_dot + 1 ) );
    }

    std::string get_path( const std::string& request_target ) {
        return request_target.substr( 0, request_target.find( '?' ) );
    }

    std::optional<file_extension> string_to_file_extension( const std::string& file_extension_string ) {
        if ( file_extension_string == "m3u8" ) return file_extension::M3U8;
        return std::nullopt;
    }

    std::optional<std::string> file_extension_to_string( file_extension extension ) {
        if ( extension == file_extension::TS ) return "ts";
        return std::nullopt;
    }

    std::expected<mime_type,http_parse_error> get_mime_type_from_ethernet( std::span<const unsigned char> ethernet_frame ) {
        auto maybe_headers = get_http_headers_from_payload( ethernet_frame );
        if ( !maybe_headers ) {
            return std::unexpected( maybe_headers.error() );
        }
        auto headers = *maybe_headers;
        auto maybe_mime_type = string_to_mime_type( headers[ "Content-Type" ] );
        if ( !maybe_mime_type ) {
            return std::unexpected( http_parse_error::UNRECOGNIZED_MIME_TYPE );
        }
        return maybe_mime_type.value();
    }

    std::optional<mime_type> string_to_mime_type( const std::string& mime_type_string ) {
        std::cout << mime_type_string << std::endl;
        if ( mime_type_string == "text/plain" ) return mime_type::TEXT_PLAIN;
        if ( mime_type_string == "application/vnd.apple.mpegurl" ) return mime_type::APPLICATION_VND_APPLE_MPEGURL;
        return std::nullopt;
    }

    std::string write_to_file( const std::vector<uint8_t>& data, file_extension extension ) {
        auto now = std::chrono::system_clock::now();
        auto now_ms = std::chrono::duration_cast<std::chrono::milliseconds>( now.time_since_epoch() ).count();
        std::ostringstream oss;
        oss << now_ms << "." << file_extension_to_string( extension ).value();
        std::string filename = oss.str();
        std::ofstream out( filename, std::ios::binary );
        if ( !out ) {
            throw std::runtime_error( "Failed to open file for writing: " + filename );
        }
        out.write( reinterpret_cast<const char*>( data.data()), data.size() );
        out.close();
        return filename; 
    }

} // namespace ntk

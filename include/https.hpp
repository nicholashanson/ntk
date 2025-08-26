#ifndef HTTPS_HPP
#define HTTPS_HPP

#include <tls.hpp>
#include <http.hpp>

namespace ntk {

    struct incomplete_request_response {
        std::optional<http_request> request;
        std::optional<incomplete_http_response> response;

        void reset() {
            request = std::nullopt;
            response = std::nullopt;
        }
    };

    class https_live_stream : public tls_live_stream {
        public:
            https_live_stream( const four_tuple& four, std::string ssl_keys_log )
            : tls_live_stream( four, ssl_keys_log ) {}
            bool feed( const std::vector<uint8_t>& packet );
        private:
            std::vector<std::pair<http_request,http_response>> m_request_response;
            incomplete_request_response m_incomplete_request_response;
            std::optional<mime_type> m_expected_data;
            std::optional<std::string> m_name_of_written_file;
            friend class https_live_stream_friend_helper;
    };

    class https_live_stream_friend_helper {
        public:
            static incomplete_request_response get_incomplete_request_response( const https_live_stream& h );
            static std::optional<mime_type> expected_data( const https_live_stream& h );
            static std::optional<std::string> name_of_written_file( const https_live_stream& h );
    };

} // namespace ntk

#endif // HTTPS_HPP
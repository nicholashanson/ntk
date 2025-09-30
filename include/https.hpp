#ifndef HTTPS_HPP
#define HTTPS_HPP

#include <tls.hpp>
#include <http.hpp>

namespace ntk {

    // =============================
    //  Incomplete Request Response
    // =============================

    struct incomplete_request_response {
        std::optional<http_request> request;
        std::optional<incomplete_http_response> response;

        void reset() {
            request = std::nullopt;
            response = std::nullopt;
        }
    };

    // ===================
    //  HTTPS Live Stream
    // ===================

    class https_live_stream : public tls_live_stream {
        public:
            https_live_stream( const four_tuple& four, std::string ssl_keys_log )
            : tls_live_stream( four, ssl_keys_log ) {}
            std::expected<bool,std::string> feed( std::span<const uint8_t> packet );
            std::optional<std::string> get_file_written();
        private:
            std::vector<std::pair<http_request,http_response>> m_request_response;
            incomplete_request_response m_incomplete_request_response;
            std::optional<mime_type> m_expected_data;
            std::optional<std::string> m_name_of_written_file;
            bool m_is_complete;
            std::optional<bool> handle_single_record();
            bool handle_http_request(); 
            bool handle_http_response();
            bool handle_multiple_records();
            friend class https_live_stream_friend_helper;
    };

    // =================================
    //  HTTPS Live Stream Friend Helper
    // =================================

    class https_live_stream_friend_helper {
        public:
            static incomplete_request_response get_incomplete_request_response( const https_live_stream& h );
            static std::optional<mime_type> expected_data( const https_live_stream& h );
            static std::optional<std::string> name_of_written_file( const https_live_stream& h );
            static bool is_complete( const https_live_stream& h );
    };

    // ===========================
    //  HTTPS Live Stream Session
    // ===========================

    class https_live_stream_session {
        public:
            https_live_stream_session( std::string ssl_keys_log );
            std::size_t number_of_completed_transfers;
            bool feed( std::span<const uint8_t> packet );
            std::optional<std::vector<std::string>> get_files_written();
        private:
            std::vector<std::string> get_new_files_written();
            std::vector<std::unique_ptr<https_live_stream>> m_live_streams;
            std::unordered_set<four_tuple> m_four_tuples;
            std::optional<std::vector<std::string>> m_files_written;
            std::string m_ssl_keys_log;
            friend class https_live_stream_session_friend_helper;
    };

    // =========================================
    //  HTTPS Live Stream Session Friend Helper
    // =========================================

    class https_live_stream_session_friend_helper {
        public:
            static const std::unique_ptr<https_live_stream>& get_live_stream( const https_live_stream_session& h, const four_tuple& four );
            static const std::vector<std::unique_ptr<https_live_stream>>& live_streams( const https_live_stream_session& h );
            static const std::unordered_set<four_tuple>& four_tuples( const https_live_stream_session& h );
            static std::optional<std::vector<std::string>> files_written( const https_live_stream_session& h );
    };

} // namespace ntk

#endif // HTTPS_HPP/
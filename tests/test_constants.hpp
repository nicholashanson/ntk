#ifndef TEST_CONSTANTS
#define TEST_CONSTANTS

namespace test {

    inline std::string packet_data_dir = "../packet_data";

    inline std::map<std::string,std::string> packet_data_files = {
        { "lena", packet_data_dir + "/lena.txt" },
        { "checkerboard", packet_data_dir + "/checkerboard.txt" },
        { "color", packet_data_dir + "/color.txt" },
        { "tiny_cross", packet_data_dir + "/tiny_cross.txt" },
        { "tls_handshake", packet_data_dir + "/tls_handshake.txt" },
        { "earth_cam_live_stream", packet_data_dir + "/earth_cam_live_stream.txt" },
        { "earth_cam_video", packet_data_dir + "/earth_cam_video.txt" },
        { "earth_cam_static", packet_data_dir + "/static_earth_cam.txt" },
        { "short_stream", packet_data_dir + "/192.168.0.21_48662_204.107.64.57_443.txt" },
        { "long_stream", packet_data_dir + "/192.168.0.21_48658_204.107.64.57_443.txt" },
        { "segment_capture", packet_data_dir + "/segment_capture.txt" },
        { "segment_capture_crash", packet_data_dir + "/segment_capture_crash.txt" } 
    };

    enum class tls_handshake : uint8_t {
        SYN,
        SYNACK,
        ACK,
        RST = 17
    };

    enum class tiny_cross : uint8_t {
        SYN,
        SYNACK,
        ACK,
        INITIATOR_FIN  = 9,
        RESPONDER_FIN,
        INITIATOR_ACK,
        RESPONDER_ACK
    };

    enum class checkerboard : uint8_t {
        SYN,
        SYNACK,
        ACK
    };

    template<typename T>
    constexpr std::size_t to_index( T val ) {
        return static_cast<std::size_t>( val );
    }

    //inline const unsigned char http_partial_request[] = {}

    inline const unsigned char mp4_meta_data[] = {
        /* ftyp box ( file type box ) */                                /* ftyp box ( file type box ) */
        0x00, 0x00, 0x00, 0x20,                                         // length : 32 bytes
        0x66, 0x74, 0x79, 0x70,                                         // ftyp
        0x69, 0x73, 0x6f, 0x6d,                                         // major brand : isom
        0x00, 0x00, 0x02, 0x00,                                         // minor version                  
        /* compatible brands */                                         /* compatible brands */
        0x69, 0x73, 0x6f, 0x6d,                                         // isom: ISO Base Media File Format  
        0x69, 0x73, 0x6f, 0x32,                                         // iso2: ISO BMFF Version 2
        0x61, 0x76, 0x63, 0x31,                                         // avc1: AVC/H.264 video
        0x6d, 0x70, 0x34, 0x31,                                         // mp41: MPEG-4 version 1
        /* moov Box */                                                  /* moov Box */
        0x00, 0x00, 0x00, 0x6c,                                         // size: 108 bytes
        0x6d, 0x6f, 0x6f, 0x76,                                         // moov Box ( Movie Box )
        0x6d, 0x76, 0x68, 0x64,                                         // mvhd
        0x00,                                                           // version
        0x00, 0x00, 0x00,                                               // flags
        0x00, 0x00, 0x00, 0x00,                                         // creation time
        0x00, 0x00, 0x00, 0x00,                                         // modification time
        0x00, 0x00, 0x03, 0xe8,                                         // timescale = 1000
        0x00, 0x02, 0x79, 0xe9,                                         // duration = 162,153
        /* rate ( 16.16 fixed ) = 1.0 */                                
        0x00, 0x01, 0x00, 0x00,                                         
        /* volume ( 8.8 fixed ) = 1.0 */                                
        0x01, 0x00,                                                     
        /* reserved 2 bytes */                                          
        0x00, 0x00,                                                     
        /* reserved 8 bytes ( 2 × 4 bytes ) */                          
        0x00, 0x00, 0x00, 0x00,                                         
        0x00, 0x00, 0x00, 0x00,                                         
        /* matrix structure ( 36 bytes ) */                             /* matrix structure ( 36 bytes ) */
        0x00, 0x01, 0x00, 0x00,                                         // [0][0] = 1.0
        0x00, 0x00, 0x00, 0x00,                                         // [0][1] = 0.0
        0x00, 0x00, 0x00, 0x00,                                         // [0][2] = 0.0
        0x00, 0x01, 0x00, 0x00,                                         // [1][0] = 1.0 
        0x00, 0x00, 0x00, 0x00,                                         // [1][1] = 0.0
        0x00, 0x00, 0x00, 0x00,                                         // [1][2] = 0.0
        0x00, 0x00, 0x40, 0x00,                                         // [2][0] = 16384 (fixed-point)
        0x00, 0x00, 0x00, 0x00,                                         // [2][1] = 0
        0x00, 0x00, 0x00, 0x00,                                         // [2][2] = 0
        /* pre-defined ( reserved 24 bytes ) */                         
        0x00, 0x00, 0x00, 0x00,                                         
        0x00, 0x00, 0x00, 0x00,                                         
        0x00, 0x00, 0x00, 0x00,                                         
        0x00, 0x00, 0x00, 0x00,                                                                     
        0x00, 0x00, 0x00, 0x00,                                         
        0x00, 0x00, 0x00, 0x00,                                         
        /* next track ID */
        0x00, 0x00, 0x03, 0x00                                              
    };                                                                  

    inline const unsigned char http_get_packet[] = {                    
        /* ethernet header */                                           /* ethernet header */
        0x14, 0xf6, 0xd8, 0xaa, 0x69, 0xfa,                             // destination MAC address ( server )
        0x42, 0x8b, 0x4e, 0x1a, 0xce, 0xd9,                             // source MAC address ( client )
        0x08, 0x00,                                                     // ether-type
        /* ipv4 header */                                               /* ipv4 header */
        0x45,                                                           // version ( 4 ) + ihl ( 5 )
        0x00,                                                           // DSCP + ECN
        0x01, 0x96,                                                     // total-length: 406 bytes
        0x44, 0xed,                                                     // identification
        0x40, 0x00,                                                     // flags + fragment offset
        0x40,                                                           // TTL
        0x06,                                                           // protocol ( TCP )
        0x72, 0xfb,                                                     // header checksum
        0xc0, 0xa8, 0x00, 0x14,                                         // source ip: 192.168.0.20
        0xc0, 0xa8, 0x00, 0x15,                                         // destination ip: 192.168.0.21
        /* tcp header */                                                /* tcp header */
        0xac, 0x18,                                                     // Source port: 44056
        0x0b, 0xb8,                                                     // destination port: 3000
        0xb9, 0x20, 0xc9, 0xb4,                                         // sequence number
        0xd3, 0xc1, 0xea, 0x0a,                                         // acknowledgment number
        0x80,                                                           // data offset ( 8 ) << 4, reserved
        0x18,                                                           // flags: PSH + ACK
        0x00, 0x80,                                                     // window size
        0x4b, 0x81,                                                     // checksum
        0x00, 0x00,                                                     // urgent pointer
        /* tcp options */                                               /* trcp options */
        0x01,                                                           // NOP
        0x01,                                                           // NOP
        0x08, 0x0a, 0x02, 0x0d, 0x72, 0x9a, 0x58, 0x64, 0xbc, 0x69,     // timestamp            
        /* HTTP GET request */                                          /* HTTP GET request */
        // Request Line: "GET / HTTP/1.1\r\n"                           // Request Line: "GET / HTTP/1.1\r\n"   
        0x47, 0x45, 0x54,                                               // GET
        0x20,                                                           // ( space )
        0x2f,                                                           // /
        0x20,                                                           // ( space )
        0x48, 0x54, 0x54, 0x50,                                         // HTTP
        0x2f,                                                           // /
        0x31, 0x2e, 0x31,                                               // 1.1    
        0x0d, 0x0a,                                                     // \r\n
        // Header: "Host: 192.168.0.21:3000\r\n"                        // Header: "Host: 192.168.0.21:3000\r\n"                        
        0x48, 0x6f, 0x73, 0x74,                                         // Host
        0x3a,                                                           // :
        0x20,                                                           // ( space )
        0x31, 0x39, 0x32, 0x2e,                                         // 192. 
        0x31, 0x36, 0x38, 0x2e,                                         // 168.
        0x30, 0x2e, 0x32, 0x31,                                         // 0.21
        0x3a,                                                           // :
        0x33, 0x30, 0x30, 0x30,                                         // 3000
        0x0d, 0x0a,                                                     // \r\n
        // Header: "User-Agent: Mozilla/5.0 (Android 14; Mobile; rv:109.0) Gecko/112.0 Firefox/112.0\r\n"
        0x55, 0x73, 0x65, 0x72,                                         // User
        0x2d,                                                           // -
        0x41, 0x67, 0x65, 0x6e, 0x74,                                   // Agent
        0x3a,                                                           // :
        0x20,                                                           // ( space )
        0x4d, 0x6f, 0x7a, 0x69, 0x6c, 0x6c, 0x61,                       // Mozilla
        0x2f,                                                           // /
        0x35, 0x2e, 0x30,                                               // 5.0
        0x20,                                                           // ( space )
        0x28,                                                           // (
        0x41, 0x6e, 0x64, 0x72, 0x6f, 0x69, 0x64,                       // Android
        0x20,                                                           // ( space )
        0x31, 0x34,                                                     // 14   
        0x3b,                                                           // ;
        0x20,                                                           // ( space )
        0x4d, 0x6f, 0x62, 0x69, 0x6c, 0x65,                             // Mobile
        0x3b,                                                           // ;
        0x20,                                                           // ( space )
        0x72, 0x76, 0x3a, 0x31, 0x30, 0x39, 0x2e, 0x30,                 // rv:109.0
        0x29,                                                           // )
        0x20,                                                           // ( space )
        0x47, 0x65, 0x63, 0x6b, 0x6f,                                   // Gecko
        0x2f,                                                           // /
        0x31, 0x31, 0x32, 0x2e, 0x30,                                   // 112.0
        0x20,                                                           // ( space )
        0x46, 0x69, 0x72, 0x65, 0x66, 0x6f, 0x78,                       // Firefox
        0x2f,                                                           // /
        0x31, 0x31, 0x32, 0x2e, 0x30,                                   // 112.0
        0x0d, 0x0a,                                                     // \r\n
        // Header: "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8\r\n"
        0x41, 0x63, 0x63, 0x65, 0x70, 0x74,                             // Accept
        0x3a,                                                           // ; 
        0x20,                                                           // ( space )
        0x74, 0x65, 0x78, 0x74,                                         // text
        0x2f,                                                           // /
        0x68, 0x74, 0x6d, 0x6c,                                         // "html
        0x2c,                                                           // ,
        0x61, 0x70, 0x70, 0x6c, 0x69, 0x63,                             // applic
        0x61, 0x74, 0x69, 0x6f, 0x6e,                                   // ation
        0x2f,                                                           // /
        0x78, 0x68, 0x74, 0x6d, 0x6c,                                   // xhtml
        0x2b,                                                           // +
        0x78, 0x6d, 0x6c,                                               // xml
        0x2c,                                                           // ,
        0x61, 0x70, 0x70, 0x6c, 0x69, 0x63,                             // applica
        0x61, 0x74, 0x69, 0x6f, 0x6e,                                   // ation
        0x2f,                                                           // /
        0x78, 0x6d, 0x6c,                                               // xml
        0x3b, 0x71, 0x3d, 0x30, 0x2e, 0x39,                             // ;q=0.9
        0x2c,                                                           // ,
        0x69, 0x6d, 0x61, 0x67, 0x65,                                   // image
        0x2f,                                                           //
        0x61, 0x76, 0x69, 0x66,                                         // avif
        0x2c,                                                           // ,
        0x69, 0x6d, 0x61, 0x67, 0x65,                                   // image                       
        0x2f,                                                           // /
        0x77, 0x65, 0x62, 0x70,                                         // webp
        0x2c,                                                           // ,
        0x2a, 0x2f, 0x2a,                                               // */*
        0x3b, 0x71, 0x3d, 0x30, 0x2e, 0x38,                             // ;q=0.8"
        0x0d, 0x0a,                                                     // \r\n
        // Header: "Accept-Language:                                    // Header: "Accept-Language: 
        // en-GB,en-US;q=0.7,zh-CN;q=0.3\r\n"                           // en-GB,en-US;q=0.7,zh-CN;q=0.3\r\n" 
        0x41, 0x63, 0x63, 0x65, 0x70, 0x74,                             // Accept
        0x2d,                                                           // -
        0x4c, 0x61, 0x6e, 0x67, 0x75, 0x61, 0x67, 0x65,                 // Language
        0x3a,                                                           // :
        0x20,                                                           // ( space )                    
        0x65, 0x6e, 0x2d, 0x47, 0x42,                                   // "en-GB"
        0x2c,                                                           // ','
        0x65, 0x6e, 0x2d, 0x55, 0x53,                                   // "en-US"
        0x3b, 0x71, 0x3d, 0x30, 0x2e, 0x37,                             // ";q=0.7"
        0x2c,                                                           // ','
        0x7a, 0x68, 0x2d, 0x43, 0x4e,                                   // "zh-CN"
        0x3b, 0x71, 0x3d, 0x30, 0x2e, 0x33,                             // ";q=0.3"
        0x0d, 0x0a,                                                     // '\r\n'
        // Header: "Accept-Encoding: gzip, deflate\r\n"                 // Header: "Accept-Encoding: gzip, deflate\r\n"     
        0x41, 0x63, 0x63, 0x65, 0x70, 0x74,                             // Accept
        0x2d,                                                           // -               
        0x45, 0x6e, 0x63, 0x6f, 0x64, 0x69, 0x6e, 0x67,                 // Encoding             
        0x3a,                                                           // :
        0x20,                                                           // ( space )                     
        0x67, 0x7a, 0x69, 0x70,                                         // "gzip"
        0x2c, 0x20,                                                     // ", "
        0x64, 0x65, 0x66, 0x6c, 0x61, 0x74, 0x65,                       // "deflate"
        0x0d, 0x0a,                                                     // '\r\n'
        // Header: "Connection: keep-alive\r\n"                         // Header: "Connection: keep-alive\r\n"   
        0x43, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e,     // Connection
        0x3a,                                                           // :
        0x20,                                                           // ( space )
        0x6b, 0x65, 0x65, 0x70, 0x2d, 0x61, 0x6c, 0x69, 0x76, 0x65,     // "keep-alive"
        0x0d, 0x0a,                                                     // '\r\n'
        // Header: "Upgrade-Insecure-Requests: 1\r\n"                   // Header: "Upgrade-Insecure-Requests: 1\r\n"   
        0x55, 0x70, 0x67, 0x72, 0x61, 0x64, 0x65,                       // Upgrade            
        0x2d,                                                           // -
        0x49, 0x6e, 0x73, 0x65, 0x63, 0x75, 0x72, 0x65,                 // Insecure
        0x2d,                                                           // -
        0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x73,                 // Requests
        0x3a,                                                           // : 
        0x20,                                                           // ( space ) 
        0x31,                                                           // 1
        0x0d, 0x0a,                                                     // \r\n                                                                 
        0x0d, 0x0a                                                      // \r\n                                     
    };                                                                  

    inline const unsigned char tcp_ack_get_packet[] = {                 
        /* ethernet header */                                           /* ethernet header */
        0x14, 0xf6, 0xd8, 0xaa, 0x69, 0xfa,                             // destination mac address
        0x42, 0x8b, 0x4e, 0x1a, 0xce, 0xd9,                             // source mac address
        0x08, 0x00,                                                     // ether-type
        /* ipv4 header */                                               /* ipv4 header */
        0x45,                                                           // version = 4, header length = 5 * 4 = 20 bytes
        0x00,                                                           // DSCP and ECN
        0x00, 0x34,                                                     // total length of packet
        0x80, 0x9c,                                                     // identification
        0x40, 0x00,                                                     // flags and fragment offset
        0x40,                                                           // time-to-live
        0x06,                                                           // TCP protocol
        0x38, 0xae,                                                     // header checksum
        0xc0, 0xa8, 0x00, 0x15,                                         // source ip address
        0xc0, 0xa8, 0x00, 0x14,                                         // destination ip address
        /* tcp header */                                                /* tcp header */
        0x0b, 0xb8,                                                     // source port
        0xac, 0x18,                                                     // destination port
        0xd3, 0xc1, 0xea, 0x0a,                                         // sequence number
        0xb9, 0x20, 0xcb, 0x16,                                         // acknowledgment number      
        0x80,                                                           // data offset and reserved
        0x10,                                                           // flags ( ACK )
        0x01, 0xfb,                                                     // window size
        0x81, 0xa0,                                                     // checksum
        0x00, 0x00,                                                     // urgent pointer
        /* tcp options */                                               /* tcp options */
        0x01,                                                           // NOP
        0x01,                                                           // NOP
        0x08, 0x0a, 0x58, 0x64, 0xbc, 0x6f, 0x02, 0x0d, 0x72, 0x9a      // timestamp
    };    

    inline const unsigned char http_response_packet[] = {
        /* ethernet header */                                           /* ethernet header */
        0x42, 0x8b, 0x4e, 0x1a, 0xce, 0xd9,                             // destination mac address
        0x14, 0xf6, 0xd8, 0xaa, 0x69, 0xfa,                             // source mac address
        0x08, 0x00,                                                     // ether-type
        /* ipv4 header */                                               /* IPv4 header */
        0x45,                                                           // version = 4, header length = 5 * 4 = 20 bytes
        0x00,                                                           // DSCP and ECN
        0x01, 0x03,                                                     // total length of packet
        0x80, 0x9d,                                                     // identification
        0x40, 0x00,                                                     // flags and fragment offset
        0x40,                                                           // time-to-live
        0x06,                                                           // tcp protocol
        0x37, 0xde,                                                     // header checksum
        0xc0, 0xa8, 0x00, 0x15,                                         // source IP address
        0xc0, 0xa8, 0x00, 0x14,                                         // destination IP address
        /* tcp header */                                                /* tcp header */
        0x0b, 0xb8,                                                     // source port
        0xac, 0x18,                                                     // destination port
        0xd3, 0xc1, 0xea, 0x0a,                                         // sequence number
        0xb9, 0x20, 0xcb, 0x16,                                         // acknowledgment number
        0x80,                                                           // data offset and reserved
        0x18,                                                           // flags ( ACK ) 
        0x01, 0xfb,                                                     // window size
        0x82, 0x6f,                                                     // checksum
        0x00, 0x00,                                                     // urgent pointer
        /* tcp options */                                               /* tcp options */
        0x01, 0x01,                                                     // NOP
        0x08, 0x0a, 0x58, 0x64, 0xbc, 0x70, 0x02, 0x0d, 0x72, 0x9a,     // timestamp 
        /* http response */                                             /* http response */
        /* http version and status code */                              /* http version and status code */
        0x48, 0x54, 0x54, 0x50,                                         // HTTP
        0x2f,                                                           // / 
        0x31, 0x2e, 0x31,                                               // 1.1
        0x20,                                                           // ( space )
        0x32, 0x30, 0x30,                                               // 200
        0x20,                                                           // ( space )
        0x4f, 0x4b,                                                     // OK
        0x0d, 0x0a,                                                     // \n
        /* headers */                                                   /* headers */
        /* Content-Type: text/plain */                                  /* Content-Type: text/plain */
        0x43, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74,                       // Content
        0x2d,                                                           // -
        0x54, 0x79, 0x70, 0x65,                                         // Type
        0x3a,                                                           // :
        0x20,                                                           // ( space )
        0x74, 0x65, 0x78,0x74,                                          // text                                                           
        0x2f,                                                           // /
        0x70, 0x6c, 0x61, 0x69, 0x6e, // text/                          // plain                     
        0x0d, 0x0a,                                                     // \n
        /* Date: Tue, 13 May 2025 08:07:35 GMT */                       /* Date: Tue, 13 May 2025 08:07:35 GMT */
        0x44, 0x61, 0x74, 0x65,                                         // Date                               
        0x3a,                                                           // :
        0x20,                                                           // ( space )
        0x54, 0x75, 0x65,                                               // Tue 
        0x2c,                                                           // ,
        0x20,                                                           // ( space )
        0x31, 0x33,                                                     // 13
        0x20,                                                           // ( space )
        0x4d, 0x61, 0x79,                                               // May
        0x20,                                                           // ( space )
        0x32, 0x30, 0x32, 0x35,                                         // 2025
        0x20,                                                           // ( space )
        0x30, 0x38, 0x3a, 0x30, 0x37, 0x3a, 0x33, 0x35,                 // 08:07::35
        0x20,                                                           // ( space )
        0x47, 0x4d, 0x54,                                               // GMT 
        0x0d, 0x0a,                                                     // \n
        /* Connection: keep-alive */                                    /* Connection: keep-alive */
        0x43, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e,     // Connection
        0x3a,                                                           // :
        0x20,                                                           // ( space )
        0x6b, 0x65, 0x65, 0x70,                                         // keep
        0x2d,                                                           // -
        0x61, 0x6c, 0x69, 0x76, 0x65,                                   // alive
        0x0d, 0x0a,                                                     // \n
        /* Keep-Alive: timeout=5 */                                     /* Keep-Alive: timeout=5 */
        0x4b, 0x65, 0x65, 0x70,                                         // Keep
        0x2d,                                                           // -
        0x41, 0x6c, 0x69, 0x76, 0x65,                                   // Alive
        0x3a,                                                           // :
        0x20,                                                           // ( space )
        0x74, 0x69, 0x6d, 0x65,                                         // time
        0x6f, 0x75, 0x74,                                               // out
        0x3d,                                                           // =
        0x35,                                                           // 5
        0x0d, 0x0a,                                                     // \n 
        /* Transfer-Encoding: chunked */                                /* Transfer-Encoding: chunked */
        0x54, 0x72, 0x61, 0x6e, 0x73, 0x66, 0x65, 0x72,                 // Transfer
        0x2d,                                                           // -
        0x45, 0x6e, 0x63, 0x6f, 0x64, 0x69, 0x6e, 0x67,                 // Encoding
        0x3a,                                                           // :
        0x20,                                                           // ( space )
        0x63, 0x68, 0x75, 0x6e, 0x6b, 0x65, 0x64,                       // chunked
        /* end of headers */                                            /* end of headers */
        0x0d, 0x0a,                                                     // \n
        0x0d, 0x0a,                                                     // \n
        /* http body */                                                 /* http body */
        // "Hello, World from Node.js HTTP server!\n"                   // "Hello, World from Node.js HTTP server!\n"
        0x32, 0x37,                                                     // chunk length 
        0x0d, 0x0a,                                                     // \r\n 
        0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x2c,                             // Hello,
        0x20,                                                           // ( space )
        0x57, 0x6f, 0x72, 0x6c, 0x64,                                   // World
        0x20,                                                           // ( space ) 
        0x66, 0x72, 0x6f, 0x6d,                                         // from
        0x20,                                                           // ( space )
        0x4e, 0x6f, 0x64, 0x65, 0x2e, 0x6a, 0x73,                       // Node.js
        0x20,                                                           // ( space )
        0x48, 0x54, 0x54, 0x50,                                         // HTTP
        0x20,                                                           // ( space )
        0x73, 0x65, 0x72, 0x76, 0x65, 0x72,                             // server 
        0x21,                                                           // !                                                         
        0x0a,                                                           // \n
        0x0d, 0x0a,                                                     // end of chunk
        0x30, 0x0d, 0x0a, 0x0d, 0x0a                                    // zero-length chunk                                                
    };                                                                  

    inline const unsigned char tcp_ack_response_packet[] = {            
        /* ethernet header */                                           /* ethernet header */
        0x14, 0xf6, 0xd8, 0xaa, 0x69, 0xfa,                             // destination MAC address
        0x42, 0x8b, 0x4e, 0x1a, 0xce, 0xd9,                             // source MAC address
        0x08, 0x00,                                                     // ether-type ( ipv4 )
        /* ipv4 header */                                               /* ipv4 header */
        0x45,                                                           // version = 4, header-length = 5 (20 bytes)
        0x00,                                                           // type of service ( ToS )
        0x00, 0x34,                                                     // total length
        0x44, 0xee,                                                     // identification
        0x40, 0x00,                                                     // flags + fragment offset
        0x40,                                                           // TTL ( time-to-live )
        0x06,                                                           // protocol ( TCP )
        0x74, 0x5c,                                                     // header checksum
        0xc0, 0xa8, 0x00, 0x14,                                         // source ip address
        0xc0, 0xa8, 0x00, 0x15,                                         // destination ip address
        /* tcp header */                                                /* tcp header */
        0xac, 0x18,                                                     // source port
        0x0b, 0xb8,                                                     // destination port
        0xb9, 0x20, 0xcb, 0x16,                                         // sequence number
        0xd3, 0xc1, 0xea, 0xd9,                                         // acknowledgment number
        0x80,                                                           // data offset + reserved
        0x10,                                                           // flags ( ACK )
        0x00, 0x83,                                                     // window size
        0x70, 0x9d,                                                     // checksum
        0x00, 0x00,                                                     // urgent pointer
        /* tcp options */                                               /* tcp options */
        0x01,                                                           // NOP 
        0x01,                                                           // NOP 
        0x08, 0x0a, 0x02, 0x0d, 0x72, 0x9d, 0x58, 0x64, 0xbc, 0x70      // timestamp
    };                                                                  

    inline const unsigned char tcp_ack_of_ack_packet[] = {              
        /* ethernet header */                                           /* ethernet header */
        0x42, 0x8b, 0x4e, 0x1a, 0xce, 0xd9,                             // destination MAC address
        0x14, 0xf6, 0xd8, 0xaa, 0x69, 0xfa,                             // source MAC address
        0x08, 0x00,                                                     // ether-type ( 0x0800 = ipv4 )
        /* ipv4 Header */                                               /* ipv4 header */
        0x45,                                                           // version ( 4 ) and header-length ( 20 bytes )
        0x00,                                                           // type of service ( 0 )
        0x00, 0x34,                                                     // total-length ( 0x0034 = 52 bytes )
        0x80, 0x9e,                                                     // identification
        0x40, 0x00,                                                     // flags and fragment offset ( 0x4000, no fragmentation )
        0x40,                                                           // time-to-Live ( TTL ) = 64
        0x06,                                                           // protocol ( 0x06 = TCP )
        0x74, 0x5c,                                                     // header checksum
        0xc0, 0xa8, 0x00, 0x15,                                         // source ip address ( 192.168.0.21 )
        0xc0, 0xa8, 0x00, 0x14,                                         // destination ip address ( 192.168.0.20 )
        /* TCP Header */                                                /* tcp header */
        0x0b, 0xb8,                                                     // source port ( 0x0bb8 = 3032 )
        0xac, 0x18,                                                     // destination port ( 0xac18 = 44248 )
        0xd3, 0xc1, 0xea, 0xd9,                                         // sequence number ( 0xd3c1ead9 )
        0xb9, 0x20, 0xcb, 0x16,                                         // acknowledgment number 
        0x80,                                                           // data offset & reserved 
        0x11,                                                           // flags ( 0x11 = ACK, push flag set )
        0x01, 0xfb,                                                     // window size (0x01fb = 511)
        0x81, 0xa0,                                                     // checksum 
        0x00, 0x00,                                                     // urgent pointer 
        /* TCP Options */                                               /* tcp options */
        0x01,                                                           // NOP 
        0x01,                                                           // NOP
        0x08, 0x0a, 0x58, 0x64, 0xcf, 0xfc, 0x02, 0x0d, 0x72, 0x9d      // timestamp
    };                                                                  

    inline const unsigned char ethernet_frame_udp[] = {                 
        /* ethernet header */                                           /* ethernet header */
        0x04, 0x81, 0x9b, 0x17, 0x26, 0x81,                             // destination mac address
        0x14, 0xf6, 0xd8, 0xaa, 0x69, 0xfa,                             // source mac address
        0x08, 0x00,                                                     // ether-type
        /* ipv4 header */                                               /* ipv4 header */
        0x45,                                                           // version = 4, header-length = 5 X 4 = 20 bytes
        0x00,                                                           // DSCP and ECN
        0x00, 0x3f,                                                     // total length of packet
        0xdd, 0x2e,                                                     // identification
        0x40, 0x00,                                                     // flags and fragment offset
        0x40,                                                           // time-to-live
        0x11,                                                           // protocol
        0x00, 0x00,                                                     // header checksum
        0xc0, 0xa8, 0x00, 0x15,                                         // source ip address
        0xad, 0xc2, 0x03, 0x49,                                         // destination ip address
        /* udp header */                                                /* udp header */
        0x01, 0xbb,                                                     // source port
        0xce, 0xb9,                                                     // destination port
        0x04, 0xea,                                                     // length
        0x01, 0xb8                                                      // checksum
    };                                                                  

    inline const unsigned char ethernet_frame_tcp[] = {                 
        /* ethernet header */                                           /* ethernet header */
        0x14, 0xf6, 0xd8, 0xaa, 0x69, 0xfa,                             // destination mac address
        0x04, 0x81, 0x9b, 0x17, 0x26, 0x81,                             // source mac address
        0x08, 0x00,                                                     // ether-type 
        /* ipv4 header */                                               /* ipv4 header */
        0x45,                                                           // version = 4, ihl = 5 (20 bytes)
        0x00,                                                           // DSCP and ECN
        0x01, 0xf9,                                                     // total length = 505 bytes 
        0x34, 0x64,                                                     // identification
        0x40, 0x00,                                                     // flags + fragment offset
        0x70,                                                           // time-to-live = 112
        0x06,                                                           // protocol 
        0xbe, 0x5e,                                                     // header checksum
        0x14, 0x2a, 0x41, 0x55,                                         // source ip address = 20.42.65.85
        0xc0, 0xa8, 0x00, 0x15,                                         // destination ip address = 192.168.0.21
        /* tcp header */                                                /* tcp header */ 
        0x01, 0xbb,                                                     // source port
        0xcd, 0xcc,                                                     // destination port
        0x9f, 0xa5, 0x08, 0x57,                                         // sequence number
        0x1d, 0x42, 0x03, 0xb7,                                         // acknowledgment number
        0x50, 0x19,                                                     // data offset
        0x40, 0x02,                                                     // window size
        0x95, 0x2f,                                                     // checksum
        0x00, 0x00                                                      // urgent pointer
    };


    /*
        GET /fecnetwork/13518.flv/playlist.m3u8?t=TU3c9prX8OROLSq3b%2FYpsfc2V%2FqbTsqg%2BAb5Dc87qqe3g1hiH9ceQPI%2FhA%2BOyNoj&td=202505311249 HTTP/1.1
        Host: videos-3.earthcam.com
        User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:138.0) Gecko/20100101 Firefox/138.0
    */
    //  Accept: */*
    /*
        Accept-Language: en-US,en;q=0.5
        Accept-Encoding: gzip, deflate, br, zstd
        Origin: https://www.earthcam.com
        Connection: keep-alive
        Referer: https://www.earthcam.com/
        Sec-Fetch-Dest: empty
        Sec-Fetch-Mode: cors
        Sec-Fetch-Site: same-site
    */
    inline const unsigned char http_request_for_m3u8[] = {
        // Request Line: GET /fecnetwork/...playlist.m3u8?... HTTP/1.1
        0x47, 0x45, 0x54,                                               // "GET"
        0x20,                                                           // space
        0x2f, 0x66, 0x65, 0x63,                                         // "/fec"
        0x6e, 0x65, 0x74, 0x77, 0x6f, 0x72, 0x6b,                       // "network"
        0x2f, 0x31, 0x33, 0x35, 0x31, 0x38,                             // "/13518"
        0x2e, 0x66, 0x6c, 0x76,                                         // ".flv"
        0x2f, 0x70, 0x6c, 0x61, 0x79, 0x6c, 0x69, 0x73, 0x74,           // "/playlist"
        0x2e, 0x6d, 0x33, 0x75, 0x38,                                   // ".m3u8"
        0x3f,                                                           // '?'
        // Query string: t=...&td=...                                   // Query string: t=...&td=...
        0x74, 0x3d, 0x54, 0x55, 0x33, 0x63, 0x39, 0x70, 0x72, 
        0x58, 0x38, 0x4f, 0x52, 0x4f, 0x4c, 0x53, 0x71, 0x33, 
        0x62, 0x25, 0x32, 0x46, 0x59, 0x70, 0x73, 0x66, 0x63, 
        0x32, 0x56, 0x25, 0x32, 0x46, 0x71, 0x62, 0x54, 0x73, 
        0x71, 0x67, 0x25, 0x32, 0x42, 0x41, 0x62, 0x35, 0x44, 
        0x63, 0x38, 0x37, 0x71, 0x71, 0x65, 0x33, 0x67, 0x31, 
        0x68, 0x69, 0x48, 0x39, 0x63, 0x65, 0x51, 0x50, 0x49, 
        0x25, 0x32, 0x46, 0x68, 0x41, 0x25, 0x32, 0x42, 0x4f, 
        0x79, 0x4e, 0x6f, 0x6a, 
        0x26,                                                           // '&'
        0x74, 0x64, 0x3d,                                               // "td="
        0x32, 0x30, 0x32, 0x35,                                         // 2025
        0x30, 0x35,                                                     // 05
        0x33, 0x31,                                                     // 31
        0x31, 0x32,                                                     // 12
        0x34, 0x39,                                                     // 49
        0x20, 0x48, 0x54, 0x54, 0x50, 0x2f, 0x31, 0x2e, 0x31,           // " HTTP/1.1"
        0x0d, 0x0a,                                                     // \r\n (end of request line)
        /* headers */                                                   /* headers */
        // Host: videos-3.earthcam.com                                  // Host: videos-3.earthcam.com
        0x48, 0x6f, 0x73, 0x74,                                         // Host
        0x3a,                                                           // :
        0x20,                                                           // (space)
        0x76, 0x69, 0x64, 0x65, 0x6f, 0x73,                             // videos 
        0x2d,                                                           // - 
        0x33,                                                           // 3 
        0x2e,                                                           // . 
        0x65, 0x61, 0x72, 0x74, 0x68,                                   // earth
        0x63, 0x61, 0x6d,                                               // cam
        0x2e,                                                           // .
        0x63, 0x6f, 0x6d,                                               // com
        0x0d, 0x0a,                                                     // \r\n

        // User-Agent
        0x55, 0x73, 0x65, 0x72, 0x2d, 0x41, 0x67, 0x65, 0x6e, 0x74, 0x3a, 0x20,
        0x4d, 0x6f, 0x7a, 0x69, 0x6c, 0x6c, 0x61, 0x2f, 0x35, 0x2e, 0x30, 0x20,
        0x28, 0x58, 0x31, 0x31, 0x3b, 0x20, 0x55, 0x62, 0x75, 0x6e, 0x74, 0x75, 0x3b, 0x20,
        0x4c, 0x69, 0x6e, 0x75, 0x78, 0x20, 0x78, 0x38, 0x36, 0x5f, 0x36, 0x34, 0x3b, 0x20,
        0x72, 0x76, 0x3a, 0x31, 0x33, 0x38, 0x2e, 0x30, 0x29, 0x20,
        0x47, 0x65, 0x63, 0x6b, 0x6f, 0x2f, 0x32, 0x30, 0x31, 0x30, 0x30, 0x31, 0x30, 0x31,
        0x20, 0x46, 0x69, 0x72, 0x65, 0x66, 0x6f, 0x78, 0x2f, 0x31, 0x33, 0x38, 0x2e, 0x30,
        0x0d, 0x0a,

        // Accept
        0x41, 0x63, 0x63, 0x65, 0x70, 0x74, 0x3a, 0x20, 0x2a, 0x2f, 0x2a, 0x0d, 0x0a,

        // Accept-Language
        0x41, 0x63, 0x63, 0x65, 0x70, 0x74, 0x2d, 0x4c, 0x61, 0x6e, 0x67, 0x75, 0x61, 0x67, 0x65, 0x3a, 0x20,
        0x65, 0x6e, 0x2d, 0x55, 0x53, 0x2c, 0x65, 0x6e, 0x3b, 0x71, 0x3d, 0x30, 0x2e, 0x35, 0x0d, 0x0a,

        // Accept-Encoding
        0x41, 0x63, 0x63, 0x65, 0x70, 0x74, 0x2d, 0x45, 0x6e, 0x63, 0x6f, 0x64, 0x69, 0x6e, 0x67, 0x3a, 0x20,
        0x67, 0x7a, 0x69, 0x70, 0x2c, 0x20, 0x64, 0x65, 0x66, 0x6c, 0x61, 0x74, 0x65, 0x2c, 0x20, 0x62, 0x72,
        0x2c, 0x20, 0x7a, 0x73, 0x74, 0x64, 0x0d, 0x0a,

        // Origin
        0x4f, 0x72, 0x69, 0x67, 0x69, 0x6e, 0x3a, 0x20,
        0x68, 0x74, 0x74, 0x70, 0x73, 0x3a, 0x2f, 0x2f,
        0x77, 0x77, 0x77, 0x2e, 0x65, 0x61, 0x72, 0x74,
        0x68, 0x63, 0x61, 0x6d, 0x2e, 0x63, 0x6f, 0x6d,
        0x0d, 0x0a,

        // Connection
        0x43, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x3a, 0x20,
        0x6b, 0x65, 0x65, 0x70, 0x2d, 0x61, 0x6c, 0x69, 0x76, 0x65, 0x0d, 0x0a,

        // Referer
        0x52, 0x65, 0x66, 0x65, 0x72, 0x65, 0x72, 0x3a, 0x20,
        0x68, 0x74, 0x74, 0x70, 0x73, 0x3a, 0x2f, 0x2f,
        0x77, 0x77, 0x77, 0x2e, 0x65, 0x61, 0x72, 0x74,
        0x68, 0x63, 0x61, 0x6d, 0x2e, 0x63, 0x6f, 0x6d,
        0x2f, 0x0d, 0x0a,
        // Sec-Fetch-Dest
        0x53, 0x65, 0x63,                                               // Sec
        0x2d,                                                           // -
        0x46, 0x65, 0x74, 0x63, 0x68,                                   // Fetch
        0x2d,                                                           // -
        0x44, 0x65, 0x73, 0x74,                                         // Dest
        0x3a, 0x20,                                                     // :
        0x65, 0x6d, 0x70, 0x74, 0x79,                                   // empty
        0x0d, 0x0a,                                                     // header
        // Sec-Fetch-Mode                                               // Sec-Fetch-Mode
        0x53, 0x65, 0x63,                                               // Sec
        0x2d,                                                           //
        0x46, 0x65, 0x74, 0x63, 0x68,                                   // Fetch
        0x2d,                                                           // -
        0x4d, 0x6f, 0x64, 0x65,                                         // Mode
        0x3a, 0x20,                                                     // :
        0x63, 0x6f, 0x72, 0x73,                                         // cors 
        0x0d, 0x0a,                                                     // end of header
        // Sec-Fetch-Site : same-site                                   // Sec-Fetch-Site : same-site                                                                                                    
        0x53, 0x65, 0x63,                                               // Sec
        0x2d,                                                           // -
        0x46, 0x65, 0x74, 0x63, 0x68,                                   // Fetch
        0x2d,                                                           // -
        0x53, 0x69, 0x74, 0x65,                                         // Site
        0x3a, 0x20,                                                     // :
        0x73, 0x61, 0x6d, 0x65,                                         // same
        0x2d,                                                           // - 
        0x73, 0x69, 0x74, 0x65,                                         // site
        0x0d, 0x0a,                                                     // end of header
        0x0d, 0x0a,                                                     // end of headers
    };

    inline const unsigned char http_mpegurl_response[] = {
        // HTTP/1.1 200 OK
        0x48, 0x54, 0x54, 0x50, 
        0x2f, 
        0x31, 0x2e, 0x31,
        0x20, 
        0x32, 0x30, 0x30, 
        0x20, 
        0x4f, 0x4b, 
        0x0d, 0x0a,
        // Accept-Ranges: bytes
        0x41, 0x63, 0x63, 0x65, 0x70, 0x74, 
        0x2d, 
        0x52, 0x61, 0x6e, 0x67, 0x65, 0x73, 
        0x3a, 
        0x20, 
        0x62, 0x79, 0x74, 0x65, 0x73, 
        0x0d, 0x0a,
        // Access-Control-Expose-Headers: Date, Server, Content-Type, Content-Length, ETag
        0x41, 0x63, 0x63, 0x65, 0x73, 0x73, 
        0x2d, 
        0x43, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 
        0x2d, 
        0x45, 0x78, 0x70, 0x6f, 0x73, 0x65, 
        0x2d, 
        0x48, 0x65, 0x61, 0x64, 0x65, 0x72, 0x73, 
        0x3a, 
        0x20, 
        0x44, 0x61, 0x74, 0x65, 
        0x2c,
        0x20, 
        0x53, 0x65, 0x72, 0x76, 0x65, 0x72, 
        0x2c, 
        0x20, 
        0x43, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 
        0x2d, 
        0x54, 0x79, 0x70, 0x65, 
        0x2c,
        0x20, 
        0x43, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 
        0x2d, 
        0x4c, 0x65, 0x6e, 0x67, 0x74, 0x68, 
        0x2c, 
        0x20, 
        0x45, 0x54, 0x61, 0x67, 
        0x0d, 0x0a,
        // Cache-Control: no-cache
        0x43, 0x61, 0x63, 0x68, 0x65, 
        0x2d, 
        0x43, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 
        0x3a, 
        0x20, 
        0x6e, 0x6f, 
        0x2d, 
        0x63, 0x61, 0x63, 0x68, 0x65, 
        0x0d, 0x0a,
        // Access-Control-Allow-Origin: *
        0x41, 0x63, 0x63, 0x65, 0x73, 0x73, 
        0x2d, 
        0x43, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 
        0x2d, 
        0x41, 0x6c, 0x6c, 0x6f, 0x77, 
        0x2d, 
        0x4f, 0x72, 0x69, 0x67, 0x69, 0x6e, 
        0x3a, 
        0x20, 
        0x2a, 
        0x0d, 0x0a,
        // ETag: "<opaque hash>"
        0x45, 0x54, 0x61, 0x67, 0x3a, 0x20, 0x22, 0x50, 0x31, 
        0x52, 0x50, 0x62,
        0x6d, 0x32, 0x68, 0x38, 0x54, 0x58, 0x4e, 0x66, 0x35, 
        0x64, 0x67, 0x6c,
        0x76, 0x2f, 0x6d, 0x72, 0x72, 0x41, 0x7a, 0x49, 0x75, 
        0x6c, 0x4c, 0x39,
        0x66, 0x4e, 0x65, 0x61, 0x38, 0x4f, 0x4e, 0x6a, 0x4e, 
        0x5a, 0x65, 0x6c,
        0x30, 0x4d, 0x22, 0x0d, 0x0a,
        // Access-Control-Allow-Credentials: true
        0x41, 0x63, 0x63, 0x65, 0x73, 0x73, 
        0x2d, 
        0x43, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 
        0x2d, 
        0x41, 0x6c, 0x6c, 0x6f, 0x77, 
        0x2d, 
        0x43, 0x72, 0x65, 0x64, 0x65, 0x6e, 0x74, 0x69, 0x61, 0x6c, 0x73, 
        0x3a, 
        0x20, 
        0x74, 0x72, 0x75, 0x65, 
        0x0d, 0x0a,
        // Access-Control-Allow-Methods: OPTIONS, GET, POST, HEAD
        0x41, 0x63, 0x63, 0x65, 0x73, 0x73, 
        0x2d, 
        0x43, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 
        0x2d, 
        0x41, 0x6c, 0x6c, 0x6f, 0x77, 
        0x2d, 
        0x4d, 0x65, 0x74, 0x68, 0x6f, 0x64, 0x73, 
        0x3a, 
        0x20, 
        0x4f, 0x50, 0x54, 0x49, 0x4f, 0x4e, 0x53, 
        0x2c, 
        0x20, 
        0x47, 0x45, 0x54, 
        0x2c, 
        0x20, 
        0x50, 0x4f, 0x53, 0x54,
        0x2c, 
        0x20, 
        0x48, 0x45, 0x41, 0x44, 
        0x0d, 0x0a,
        // Connection: Keep-Alive
        0x43, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 
        0x3a, 
        0x20,
        0x4b, 0x65, 0x65, 0x70, 
        0x2d, 
        0x41, 0x6c, 0x69, 0x76, 0x65, 
        0x0d, 0x0a,
        // Content-Encoding: gzip
        0x43, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 
        0x2d, 
        0x45, 0x6e, 0x63, 0x6f, 0x64, 0x69, 0x6e, 0x67, 
        0x3a, 
        0x20, 
        0x67, 0x7a, 0x69, 0x70, 
        0x0d, 0x0a,
        // Date: Sat, 31 May 2025 16:54:56 GMT
        0x44, 0x61, 0x74, 0x65, 
        0x3a, 
        0x20, 
        0x53, 0x61, 0x74, 
        0x2c, 
        0x20, 
        0x33, 0x31, 
        0x20, 
        0x4d, 0x61, 0x79, 
        0x20, 
        0x32, 0x30, 0x32, 0x35, 
        0x20, 
        0x31, 0x36, 0x3a, 0x35, 0x34, 0x3a, 0x35, 0x36, 
        0x20, 
        0x47, 0x4d, 0x54, 
        0x0d, 0x0a,
        // Content-Type: application/vnd.apple.mpegurl                  // Content-Type: application/vnd.apple.mpegurl
        0x43, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74,                       // Content
        0x2d,                                                           // '-'
        0x54, 0x79, 0x70, 0x65,                                         // Type
        0x3a,                                                           // :
        0x20,                                                           // (space)
        0x61, 0x70, 0x70, 0x6c, 0x69, 0x63, 0x61, 0x74, 0x69,           // application 
        0x6f, 0x6e, 
        0x2f,                                                           // '/''
        0x76, 0x6e, 0x64,                                               // vnd
        0x2e,                                                           // .
        0x61, 0x70, 0x70, 0x6c, 0x65,                                   // apple
        0x2e,                                                           // .
        0x6d, 0x70, 0x65, 0x67, 0x75, 0x72, 0x6c,                       // mpegurl
        0x0d, 0x0a,                                                     // end of header
        // Content-Length: 219                                          / Content-Length: 219                              
        0x43, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74,                       // Content 
        0x2d,                                                           // -
        0x4c, 0x65, 0x6e, 0x67, 0x74, 0x68,                             // Length
        0x3a,                                                           // :
        0x20,                                                           // (space)
        0x32, 0x31, 0x39,                                               // 219
        0x0d, 0x0a,                                                     // end of header
        // End of headers
        0x0d, 0x0a,
    };

    inline const unsigned char http_chunk_list_response[] = {
        /* HTTP/1.1 200 OK Accept-Ranges: bytes Access-Control-Expose-Headers: Date, Server, Content-Type, Content-Length, ETa */
        0x48, 0x54, 0x54, 0x50,                                         // HTTP
        0x2f,                                                           // /
        0x31, 0x2e, 0x31,                                               // 1.1
        0x20,                                                           // (space)
        0x32, 0x30, 0x30,                                               // 200
        0x20,                                                           // (space)
        0x4f, 0x4b,                                                     // OK
        0x0d, 0x0a,                                                     // (CR)(LF)
        /* Accept-Ranges: bytes */                                      /* Accept-Ranges: bytes */
        0x41, 0x63, 0x63, 0x65, 0x70, 0x74,                             // Accept
        0x2d,                                                           // -
        0x52, 0x61, 0x6e, 0x67, 0x65, 0x73,                             // Ranges
        0x3a,                                                           // :
        0x20,                                                           // (space)
        0x62, 0x79, 0x74, 0x65, 0x73,                                   // bytes
        0x0d, 0x0a,                                                     // (CR)(LF)
        /* Access-Control-Expose-Headers: Date, Server, Content-Type, Content-Length, ETag */
        0x41, 0x63, 0x63, 0x65, 0x73, 0x73,                             // Access
        0x2d,                                                           // -
        0x43, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c,                       // Control
        0x2d,                                                           // -
        0x45, 0x78, 0x70, 0x6f, 0x73, 0x65,                             // Expose
        0x2d,                                                           // -
        0x48, 0x65, 0x61, 0x64, 0x65, 0x72, 0x73,                       // Headers
        0x3a,                                                           // :
        0x20,                                                           // (space)
        0x44, 0x61, 0x74, 0x65,                                         // Date
        0x2c,                                                           // ,
        0x20,                                                           // (space)
        0x53, 0x65, 0x72, 0x76, 0x65, 0x72,                             // Server
        0x2c,                                                           // ,
        0x20,                                                           // (space)
        0x43, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74,                       // Content
        0x2d,                                                           // -
        0x54, 0x79, 0x70, 0x65,                                         // Type
        0x2c,                                                           // ,
        0x20,                                                           // (space)
        0x43, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74,                       // Content
        0x2d,                                                           // -
        0x4c, 0x65, 0x6e, 0x67, 0x74, 0x68,                             // Length
        0x2c,                                                           // ,
        0x20,                                                           // (space)
        0x45, 0x54, 0x61, 0x67,                                         // ETag
        0x0d, 0x0a,                                                     // (CR)(LF)  
        /* Cache-Control: no-cache */                                   /* Cache-Control: no-cache */
        0x43, 0x61, 0x63, 0x68, 0x65,                                   // Cache
        0x2d,                                                           // -
        0x43, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c,                       // Control
        0x3a,                                                           // :
        0x20,                                                           // (space)
        0x6e, 0x6f,                                                     // no
        0x2d,                                                           // -
        0x63, 0x61, 0x63, 0x68, 0x65,                                   // cache
        0x0d, 0x0a,                                                     // (CR)(LF)
        /* Access-Control-Allow-Origin: */                              /* Access-Control-Allow-Origin: */
        0x41, 0x63, 0x63, 0x65, 0x73, 0x73,                             // Access
        0x2d,                                                           // -
        0x43, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c,                       // Control
        0x2d,                                                           // -
        0x41, 0x6c, 0x6c, 0x6f, 0x77,                                   // Allow
        0x2d,                                                           // -
        0x4f, 0x72, 0x69, 0x67, 0x69, 0x6e,                             // Origin
        0x3a,                                                           // :
        0x20,                                                           // (space)
        0x2a,                                                           // *
        0x0d, 0x0a,                                                     // (CR)(LF)
        /* ETag: "scb8jApNQFSbDkPQVFkCKY0AslhBK+bWSovKPhZlJmo" */
        0x45, 0x54, 0x61, 0x67, 0x3a, 0x20,                             // ETag:
        0x22,                                                           // "
        0x73, 0x63, 0x62, 0x38, 0x6a, 0x41, 0x70, 0x4e,                 // scb8jApN
        0x51, 0x46, 0x53, 0x62, 0x44, 0x6b, 0x50, 0x51,                 // QFSbDkPQ
        0x56, 0x46, 0x6b, 0x43, 0x4b, 0x59, 0x30, 0x41,                 // VFkCKY0A
        0x73, 0x6c, 0x68, 0x42, 0x4b, 0x2b, 0x62, 0x57,                 // slhBK+bW
        0x53, 0x6f, 0x76, 0x4b, 0x50, 0x68, 0x5a, 0x6c,                 // SovKPhZl
        0x4a, 0x6d, 0x6f, 0x22,                                         // Jmo"
        0x0d, 0x0a,                                                     // (CR)(LF)
        /* Access-Control-Allow-Credentials: true */                    /* Access-Control-Allow-Credentials: true */
        0x41, 0x63, 0x63, 0x65, 0x73, 0x73,                             // Access
        0x2d,                                                           // -
        0x43, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c,                       // Control
        0x2d,                                                           // -
        0x41, 0x6c, 0x6c, 0x6f, 0x77,                                   // Allow
        0x2d,                                                           // -
        0x43, 0x72, 0x65, 0x64, 0x65, 0x6e, 0x74, 0x69,                 // Credentials
        0x61, 0x6c, 0x73,                                 
        0x3a,                                                           // :
        0x20,                                                           // (space)
        0x74, 0x72, 0x75, 0x65,                                         // true
        0x0d, 0x0a,                                                     // (CR)(LF)
        /* Access-Control-Allow-Methods: OPTIONS, GET, POST, HEAD */
        0x41, 0x63, 0x63, 0x65, 0x73, 0x73,                             // Access
        0x2d,                                                           // -
        0x43, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c,                       // Control
        0x2d,                                                           // -
        0x41, 0x6c, 0x6c, 0x6f, 0x77,                                   // Allow
        0x2d,                                                           // -
        0x4d, 0x65, 0x74, 0x68, 0x6f, 0x64, 0x73,                       // Methods
        0x3a,                                                           // :
        0x20,                                                           // (space)
        0x4f, 0x50, 0x54, 0x49, 0x4f, 0x4e, 0x53, 0x2c,                 // OPTIONS,
        0x20,                                                           // (space)
        0x47, 0x45, 0x54, 0x2c,                                         // GET,
        0x20,                                                           // (space)
        0x50, 0x4f, 0x53, 0x54, 0x2c,                                   // POST,
        0x20,                                                           // (space)
        0x48, 0x45, 0x41, 0x44,                                         // HEAD
        0x0d, 0x0a,                                                     // (CR)(LF)
        /* Connection: Keep-Alive */                                    /* Connection: Keep-Alive */
        0x43, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e,     // Connection
        0x3a,                                                           // :
        0x20,                                                           // (space)
        0x4b, 0x65, 0x65, 0x70, 0x2d, 0x41, 0x6c, 0x69, 0x76, 0x65,     // Keep-Alive
        0x0d, 0x0a,                                                     // (CR)(LF)
        /* Content-Encoding: gzip */                                    /* Content-Encoding: gzip */
        0x43, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x2d,                 // Content-
        0x45, 0x6e, 0x63, 0x6f, 0x64, 0x69, 0x6e, 0x67,                 // Encoding
        0x3a,                                                           // :
        0x20,                                                           // (space)
        0x67, 0x7a, 0x69, 0x70,                                         // gzip
        0x0d, 0x0a                                                      // (CR)(LF)
    };

    inline const unsigned char http_request_for_ts[] = {
        0x47, 0x45, 0x54,                                               // GET
        0x20,                                                           // (space)
        0x2f,                                                           // /
        0x6d, 0x65, 0x64, 0x69, 0x61, 0x5f,                             // /media_
        0x77, 0x32, 0x39, 0x38, 0x33, 0x32, 0x35, 0x36,                 // w2983256
        0x35, 0x34, 0x5f, 0x37, 0x39, 0x35, 0x36, 0x39,                 // 54_79569.
        0x2e,                                                           // .
        0x74, 0x73, 0x3f,                                               // ts?
        0x74, 0x3d, 0x54, 0x55, 0x33, 0x63, 0x39, 0x70,                 // t=TU3c9p
        0x72, 0x58, 0x38, 0x4f, 0x52, 0x4f, 0x4c, 0x53,                 // rX8OROLS
        0x71, 0x33, 0x62,                                               // q3b
        0x25, 0x32, 0x46, 0x59, 0x70, 0x73,                             // %2FYps
        0x66, 0x63, 0x32, 0x56,                                         // fc2V
        0x25, 0x32, 0x46, 0x71, 0x62,                                   // %2Fqb
        0x54, 0x73, 0x71, 0x67,                                         // Tsqg
        0x25, 0x32, 0x42, 0x41, 0x62,                                   // %2BAb
        0x35, 0x44, 0x63, 0x38, 0x37, 0x71, 0x71, 0x65,                 // 5Dc87qqe
        0x33, 0x67, 0x31, 0x68, 0x69,                                   // 3g1hiH9c
        0x48, 0x39, 0x63, 0x65, 0x51, 0x50, 0x49,                       // eQPI
        0x25, 0x32, 0x46, 0x68, 0x41,                                   // %2FhA
        0x25, 0x32, 0x42, 0x4f, 0x79,                                   // %2BOyNoj
        0x4e, 0x6f, 0x6a,                                               // Noj
        0x26, 0x74, 0x64, 0x3d, 0x32, 0x30, 0x32, 0x35, 0x30, 0x35,     // &td=202505
        0x33, 0x31, 0x31, 0x32, 0x34, 0x39,                             // 311249
        0x20, 0x48, 0x54, 0x54, 0x50, 0x2f, 0x31, 0x2e, 0x31,           // HTTP/1.1
        0x0d, 0x0a,                                                     // \r\n
        0x48, 0x6f, 0x73, 0x74, 0x3a,                                   // Host:
        0x20, 0x76, 0x69, 0x64, 0x65, 0x6f, 0x73, 0x2d, 0x33, 0x2e,     // videos-3.
        0x65, 0x61, 0x72, 0x74, 0x68, 0x63, 0x61, 0x6d,                 // earthcam
        0x2e, 0x63, 0x6f, 0x6d,                                         // .com
        0x0d, 0x0a,                                                     // \r\n
        0x55, 0x73, 0x65, 0x72,                                         // User
        0x2d,                                                           // -
        0x41, 0x67, 0x65, 0x6e, 0x74, 0x3a,                             // Agent:
        0x20, 0x4d, 0x6f, 0x7a, 0x69, 0x6c, 0x6c, 0x61, 0x2f,           // Mozilla/
        0x35, 0x2e, 0x30,                                               // 5.0
        0x20, 0x28,                                                     // (
        0x58, 0x31, 0x31, 0x3b,                                         // X11;
        0x20, 0x55, 0x62, 0x75, 0x6e, 0x74, 0x75, 0x3b,                 // Ubuntu;
        0x20, 0x4c, 0x69, 0x6e, 0x75, 0x78,                             // Linux
        0x20, 0x78, 0x38, 0x36, 0x5f, 0x36, 0x34, 0x3b,                 // x86_64;
        0x20, 0x72, 0x76, 0x3a, 0x31, 0x33, 0x38, 0x2e, 0x30,           // rv:138.0
        0x29,                                                           // )
        0x20,                                                           // (space)
        0x47, 0x65, 0x63, 0x6b, 0x6f,                                   // Gecko/
        0x2f,                                                           // /
        0x32, 0x30, 0x31, 0x30, 0x30, 0x31, 0x30, 0x31,                 // 20100101
        0x20,                                                           // (space)
        0x46, 0x69, 0x72, 0x65, 0x66, 0x6f, 0x78, 0x2f,                 // Firefox/
        0x31, 0x33, 0x38, 0x2e, 0x30,                                   // 138.0
        0x0d, 0x0a,                                                     // \r\n
        0x41, 0x63, 0x63, 0x65, 0x70, 0x74, 0x3a,                       // Accept:
        0x20, 0x2a, 0x2f, 0x2a,                                         // */*
        0x0d, 0x0a,                                                     // \r\n
        0x41, 0x63, 0x63, 0x65, 0x70, 0x74,                             // Accept
        0x2d,                                                           // -
        0x4c, 0x61, 0x6e, 0x67, 0x75, 0x61, 0x67, 0x65, 0x3a,           // Language:
        0x20, 0x65, 0x6e, 0x2d, 0x55, 0x53, 0x2c,                       // en-US,
        0x65, 0x6e, 0x3b, 0x71, 0x3d, 0x30, 0x2e, 0x35,                 // en;q=0.5
        0x0d, 0x0a,                                                     // \r\n
        0x41, 0x63, 0x63, 0x65, 0x70, 0x74,                             // Accept
        0x2d,                                                           // -
        0x45, 0x6e, 0x63, 0x6f, 0x64, 0x69, 0x6e, 0x67, 0x3a,           // Encoding:
        0x20, 0x67, 0x7a, 0x69, 0x70, 0x2c,                             // gzip,
        0x20, 0x64, 0x65, 0x66, 0x6c, 0x61, 0x74, 0x65,                 // deflate
        0x2c, 0x20, 0x62, 0x72, 0x2c, 0x20, 0x7a, 0x73, 0x74, 0x64,     // , br, zstd
        0x0d, 0x0a,                                                     // \r\n
        0x4f, 0x72, 0x69, 0x67, 0x69, 0x6e, 0x3a,                       // Origin:
        0x20, 0x68, 0x74, 0x74, 0x70, 0x73, 0x3a, 0x2f, 0x2f,           // https:/
        0x77, 0x77, 0x77, 0x2e, 0x65, 0x61, 0x72, 0x74,                 // /www.earth
        0x68, 0x63, 0x61, 0x6d, 0x2e, 0x63, 0x6f, 0x6d,                 // cam.com
        0x0d, 0x0a,                                                     // \r\n
        0x43, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x69,                 // Connecti
        0x6f, 0x6e, 0x3a,                                               // on:
        0x20, 0x6b, 0x65, 0x65, 0x70, 0x2d, 0x61, 0x6c,                 // keep-ali
        0x69, 0x76,                                                     // ve
        0x0d, 0x0a,                                                     // \r\n
        0x52, 0x65, 0x66, 0x65, 0x72, 0x65, 0x72, 0x3a,                 // Referer:
        0x20, 0x68, 0x74, 0x74, 0x70, 0x73, 0x3a, 0x2f, 0x2f,           // https:/
        0x77, 0x77, 0x77, 0x2e, 0x65, 0x61, 0x72, 0x74,                 // /www.earth
        0x68, 0x63, 0x61, 0x6d, 0x2e, 0x63, 0x6f, 0x6d,                 // cam.com
        0x2f,                                                           // /
        0x53, 0x65, 0x63,                                               // Sec
        0x2d,                                                           // -
        0x46, 0x65, 0x74, 0x63, 0x68,                                   // Fetch
        0x2d,                                                           // -
        0x44, 0x65, 0x73, 0x74, 0x3a,                                   // Dest:
        0x65, 0x6d, 0x70, 0x74, 0x79,                                   // empty
        0x0d, 0x0a,                                                     // \r\n
        0x53, 0x65, 0x63,                                               // Sec
        0x2d,                                                           // -
        0x46, 0x65, 0x74, 0x63, 0x68,                                   // Fetch
        0x2d,                                                           // -
        0x4d, 0x6f, 0x64, 0x65, 0x3a,                                   // Mode:
        0x20, 0x63, 0x6f, 0x72, 0x73,                                   // cors
        0x0d, 0x0a,                                                     // \r\n
        // Sec-Fetch-Site : same-site                                   // Sec-Fetch-Site : same-site                                                                                                    
        0x53, 0x65, 0x63,                                               // Sec
        0x2d,                                                           // -
        0x46, 0x65, 0x74, 0x63, 0x68,                                   // Fetch
        0x2d,                                                           // -
        0x53, 0x69, 0x74, 0x65,                                         // Site
        0x3a, 0x20,                                                     // :
        0x73, 0x61, 0x6d, 0x65,                                         // same
        0x2d,                                                           // - 
        0x73, 0x69, 0x74, 0x65,                                         // site
        0x0d, 0x0a,                                                     // end of header
        0x0d, 0x0a,                                                     // end of headers
    };

    inline uint8_t ts_header[4] = { 0x47, 0x40, 0x00, 0x10 };

    inline uint8_t tls_certificate[] = { 
        0x30,                                                           // sequence tag 
        0x82,                                                           // single-byte length field
        0x03, 0xa7,                                                     // multi-byte length field
        /* tbsCertificate */                                            /* tbsCertificate */ 
        0x30,                                                           // sequence tag
        0x82,                                                           // single-byte length field
        0x03, 0x4d,                                                     // multi-byte length field


        0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x10, 0x7c, 0x42, 0xf1, 0x16, 0xac, 0xd2, 0xdf, 0x00, 0x11,
        0xe7, 0xe8, 0x19, 0x28, 0x73, 0x1e, 0xe7, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d,
        0x04, 0x03, 0x02, 0x30, 0x3b, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02,
        0x55, 0x53, 0x31, 0x1e, 0x30, 0x1c, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x13, 0x15, 0x47, 0x6f, 0x6f,
        0x67, 0x6c, 0x65, 0x20, 0x54, 0x72, 0x75, 0x73, 0x74, 0x20, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63,
        0x65, 0x73, 0x31, 0x0c, 0x30, 0x0a, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x03, 0x57, 0x45, 0x31,
        0x30, 0x1e, 0x17, 0x0d, 0x32, 0x35, 0x30, 0x35, 0x32, 0x37, 0x30, 0x37, 0x33, 0x33, 0x30, 0x38,
        0x5a, 0x17, 0x0d, 0x32, 0x35, 0x30, 0x38, 0x32, 0x35, 0x30, 0x38, 0x33, 0x33, 0x30, 0x30, 0x5a,
        0x30, 0x17, 0x31, 0x15, 0x30, 0x13, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x0c, 0x65, 0x61, 0x72,
        0x74, 0x68, 0x63, 0x61, 0x6d, 0x2e, 0x63, 0x6f, 0x6d, 0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a,
        0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07,
        0x03, 0x42, 0x00, 0x04, 0x8b, 0x0d, 0xea, 0x2f, 0x18, 0xbf, 0xed, 0xab, 0x63, 0x30, 0x9f, 0xef,
        0xd4, 0x38, 0x18, 0x81, 0x3d, 0xf9, 0x02, 0x22, 0x73, 0x42, 0x2b, 0x63, 0xe0, 0x7f, 0xa1, 0xbf,
        0x21, 0xc7, 0xfc, 0x53, 0xf2, 0x02, 0x98, 0x5b, 0x32, 0x3d, 0xb3, 0x0c, 0x39, 0xeb, 0x55, 0xa5,
        0x35, 0x06, 0x18, 0x1b, 0x73, 0x9d, 0x9b, 0x08, 0x86, 0x19, 0x7c, 0x6a, 0xa6, 0x8a, 0x9a, 0x4a,
        0x40, 0xc7, 0xd8, 0xae, 0xa3, 0x82, 0x02, 0x55, 0x30, 0x82, 0x02, 0x51, 0x30, 0x0e, 0x06, 0x03,
        0x55, 0x1d, 0x0f, 0x01, 0x01, 0xff, 0x04, 0x04, 0x03, 0x02, 0x07, 0x80, 0x30, 0x13, 0x06, 0x03,
        0x55, 0x1d, 0x25, 0x04, 0x0c, 0x30, 0x0a, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03,
        0x01, 0x30, 0x0c, 0x06, 0x03, 0x55, 0x1d, 0x13, 0x01, 0x01, 0xff, 0x04, 0x02, 0x30, 0x00, 0x30,
        0x1d, 0x06, 0x03, 0x55, 0x1d, 0x0e, 0x04, 0x16, 0x04, 0x14, 0xb1, 0x2e, 0xc8, 0x72, 0xc0, 0x37,
        0x58, 0xec, 0xd9, 0xd1, 0x9a, 0x7b, 0x45, 0xcc, 0xb7, 0x6f, 0xf5, 0xc1, 0xaf, 0xfb, 0x30, 0x1f,
        0x06, 0x03, 0x55, 0x1d, 0x23, 0x04, 0x18, 0x30, 0x16, 0x80, 0x14, 0x90, 0x77, 0x92, 0x35, 0x67,
        0xc4, 0xff, 0xa8, 0xcc, 0xa9, 0xe6, 0x7b, 0xd9, 0x80, 0x79, 0x7b, 0xcc, 0x93, 0xf9, 0x38, 0x30,
        0x5e, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x01, 0x01, 0x04, 0x52, 0x30, 0x50, 0x30,
        0x27, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x86, 0x1b, 0x68, 0x74, 0x74,
        0x70, 0x3a, 0x2f, 0x2f, 0x6f, 0x2e, 0x70, 0x6b, 0x69, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x2f, 0x73,
        0x2f, 0x77, 0x65, 0x31, 0x2f, 0x66, 0x45, 0x49, 0x30, 0x25, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05,
        0x05, 0x07, 0x30, 0x02, 0x86, 0x19, 0x68, 0x74, 0x74, 0x70, 0x3a, 0x2f, 0x2f, 0x69, 0x2e, 0x70,
        0x6b, 0x69, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x2f, 0x77, 0x65, 0x31, 0x2e, 0x63, 0x72, 0x74, 0x30,
        0x27, 0x06, 0x03, 0x55, 0x1d, 0x11, 0x04, 0x20, 0x30, 0x1e, 0x82, 0x0c, 0x65, 0x61, 0x72, 0x74,
        0x68, 0x63, 0x61, 0x6d, 0x2e, 0x63, 0x6f, 0x6d, 0x82, 0x0e, 0x2a, 0x2e, 0x65, 0x61, 0x72, 0x74,
        0x68, 0x63, 0x61, 0x6d, 0x2e, 0x63, 0x6f, 0x6d, 0x30, 0x13, 0x06, 0x03, 0x55, 0x1d, 0x20, 0x04,
        0x0c, 0x30, 0x0a, 0x30, 0x08, 0x06, 0x06, 0x67, 0x81, 0x0c, 0x01, 0x02, 0x01, 0x30, 0x36, 0x06,
        0x03, 0x55, 0x1d, 0x1f, 0x04, 0x2f, 0x30, 0x2d, 0x30, 0x2b, 0xa0, 0x29, 0xa0, 0x27, 0x86, 0x25,
        0x68, 0x74, 0x74, 0x70, 0x3a, 0x2f, 0x2f, 0x63, 0x2e, 0x70, 0x6b, 0x69, 0x2e, 0x67, 0x6f, 0x6f,
        0x67, 0x2f, 0x77, 0x65, 0x31, 0x2f, 0x74, 0x58, 0x32, 0x48, 0x35, 0x68, 0x53, 0x46, 0x77, 0x71,
        0x45, 0x2e, 0x63, 0x72, 0x6c, 0x30, 0x82, 0x01, 0x04, 0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01,
        0xd6, 0x79, 0x02, 0x04, 0x02, 0x04, 0x81, 0xf5, 0x04, 0x81, 0xf2, 0x00, 0xf0, 0x00, 0x76, 0x00,
        0x12, 0xf1, 0x4e, 0x34, 0xbd, 0x53, 0x72, 0x4c, 0x84, 0x06, 0x19, 0xc3, 0x8f, 0x3f, 0x7a, 0x13,
        0xf8, 0xe7, 0xb5, 0x62, 0x87, 0x88, 0x9c, 0x6d, 0x30, 0x05, 0x84, 0xeb, 0xe5, 0x86, 0x26, 0x3a,
        0x00, 0x00, 0x01, 0x97, 0x10, 0xdf, 0xc0, 0xc7, 0x00, 0x00, 0x04, 0x03, 0x00, 0x47, 0x30, 0x45,
        0x02, 0x21, 0x00, 0xbe, 0xa9, 0x1f, 0x4d, 0x54, 0xb5, 0x6b, 0xb6, 0xc6, 0xbf, 0xf9, 0x57, 0x65,
        0xde, 0xd0, 0x6c, 0x7f, 0x90, 0x0d, 0xb9, 0xcf, 0xc6, 0x7d, 0x29, 0x3a, 0x5c, 0xc3, 0x3a, 0xed,
        0x7b, 0x3d, 0xff, 0x02, 0x20, 0x09, 0x97, 0x88, 0x43, 0xe8, 0x1e, 0x46, 0x02, 0x22, 0xc6, 0x02,
        0xdf, 0x60, 0xa0, 0x0e, 0xac, 0x48, 0x92, 0xa5, 0x6a, 0x1d, 0xb1, 0xe9, 0xf1, 0x6e, 0x9a, 0xa8,
        0x88, 0x11, 0x6b, 0x4c, 0x94, 0x00, 0x76, 0x00, 0x7d, 0x59, 0x1e, 0x12, 0xe1, 0x78, 0x2a, 0x7b,
        0x1c, 0x61, 0x67, 0x7c, 0x5e, 0xfd, 0xf8, 0xd0, 0x87, 0x5c, 0x14, 0xa0, 0x4e, 0x95, 0x9e, 0xb9,
        0x03, 0x2f, 0xd9, 0x0e, 0x8c, 0x2e, 0x79, 0xb8, 0x00, 0x00, 0x01, 0x97, 0x10, 0xdf, 0xc4, 0xd4,
        0x00, 0x00, 0x04, 0x03, 0x00, 0x47, 0x30, 0x45, 0x02, 0x21, 0x00, 0xd9, 0x3e, 0xc7, 0xaa, 0xed,
        0x59, 0xb1, 0xb1, 0x16, 0x05, 0x12, 0x83, 0x4a, 0x61, 0x41, 0x7d, 0x4a, 0x61, 0xba, 0x55, 0x3b,
        0xb4, 0xa6, 0x28, 0xac, 0xb1, 0x9c, 0x29, 0x1d, 0x9f, 0x9b, 0xdc, 0x02, 0x20, 0x16, 0xc2, 0xe9,
        0x90, 0xde, 0x48, 0x1e, 0xbd, 0x04, 0xb2, 0x02, 0x0b, 0x4d, 0xfa, 0x80, 0x0a, 0x88, 0x8a, 0x01,
        0xcb, 0xd4, 0x55, 0x69, 0x64, 0x9d, 0x31, 0xba, 0xff, 0x19, 0x58, 0x06, 0xa9,
        /* signatureAlgorithm */                                        /* signatureAlgorithm */
        0x30,                                                           // sequence tag
        0x0a,                                                           // single-byte length field

        0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02,
        /* signature */                                                 /* signature */
        0x03,                                                           // bit-string tag
        0x48,                                                           // length
        0x00,                                                           // number of unused bits

        0x30, 0x45, 0x02, 0x20, 0x34, 0xf3, 0xae, 0x0b, 0xe9, 0x91, 0x6e, 0xee, 0x64, 0x59, 0xd3, 0xa4,
        0xf8, 0x8b, 0x26, 0x63, 0x1e, 0x54, 0x62, 0x2a, 0x17, 0x1a, 0x51, 0xae, 0x4c, 0xd1, 0x1a, 0x8e,
        0xe0, 0xa6, 0xbc, 0xd7, 0x02, 0x21, 0x00, 0xf8, 0x25, 0x79, 0xdf, 0x91, 0xa0, 0x94, 0x75, 0x5a,
        0x98, 0xa3, 0xea, 0x24, 0x8b, 0x43, 0x26, 0x63, 0xb3, 0xf3, 0x1b, 0xc9, 0x4b, 0x2c, 0x73, 0x86,
        0x53, 0x16, 0x6b, 0x7d, 0xd2, 0x82, 0xac

    };

} // test

#endif
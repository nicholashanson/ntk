#ifndef TEST_LENA_TERMINATION_HPP
#define TEST_LENA_TERMINATION_HPP

namespace test_constants {

    inline const unsigned char lena_initiator_fin[] = {
        /* ethernet header */                                           /* ethernet header */
        0x42, 0x8b, 0x4e, 0x1a, 0xce, 0xd9,                             // destination mac
        0x14, 0xf6, 0xd8, 0xaa, 0x69, 0xfa,                             // source mac
        0x08, 0x00,                                                     // ether-type: ipv4
        /* ipv4 header */                                               /* ipv4 header */
        0x45,                                                           // version + header length
        0x00,                                                           // DSCP + ECN
        0x00, 0x34,                                                     // total length = 52 bytes
        0x61, 0xf4,                                                     // identification
        0x40, 0x00,                                                     // flags + fragment offset
        0x40,                                                           // TTL
        0x06,                                                           // protocol ( TCP )
        0x57, 0x56,                                                     // header checksum
        0xc0, 0xa8, 0x00, 0x15,                                         // source ip: 192.168.0.21
        0xc0, 0xa8, 0x00, 0x14,                                         // destination ip: 192.168.0.20
        /* tcp header */                                                /* tcp header */
        0x0b, 0xb8,                                                     // source port: 3000
        0xac, 0x0e,                                                     // destination port: 44046
        0xa3, 0xbc, 0xb9, 0x2c,                                         // sequence number
        0x26, 0xeb, 0x07, 0xd5,                                         // acknowledgment number
        0x80,                                                           // data offset ( 8 * 4 = 32 ), reserved
        0x11,                                                           // flags ( FIN + ACK )
        0x01, 0xfb,                                                     // window size
        0x81, 0xa0,                                                     // checksum
        0x00, 0x00,                                                     // urgent pointer
        /* tcp options */                                               /* tcp options */
        0x01,                                                           // NOP
        0x01,                                                           // NOP
        0x08, 0x0a, 0x07, 0x8b, 0xbf, 0x7a, 0x06, 0x3d, 0xc7, 0x33      // timestamp
    };

} // namespace test_constants

#endif // TEST_LENA_TERMINATION_HPP

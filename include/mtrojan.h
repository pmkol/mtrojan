#ifndef MTROJAN_H
#define MTROJAN_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MT_MAX_ADDR_LEN 255
#define MT_FLOW_ID_LEN 8
#define MT_KEY_NONCE_LEN 12
#define MT_KEY_TCP_LEN_LEN 2
#define MT_KEY_TAG_LEN 16
#define MT_BOOTSTRAP_PAYLOAD_MAX 16384
#define MT_KEY_PLAIN_MAX 32768
#define MT_UDP_DATAGRAM_SAFE_MAX 1200

typedef enum {
    MT_OK = 0,
    MT_ERR_INVALID = -1,
    MT_ERR_AGAIN = -2,
    MT_ERR_NO_SPACE = -3
} mt_status_t;

typedef enum {
    MT_ADDR_IPV4 = 1,
    MT_ADDR_DOMAIN = 3,
    MT_ADDR_IPV6 = 4
} mt_addr_type_t;

typedef enum {
    MT_PROTECT_BOOTSTRAP = 0,
    MT_PROTECT_HANDSHAKE = 1,
    MT_PROTECT_FULL = 2
} mt_flow_protection_t;

typedef enum {
    MT_CMD_CONNECT = 0x01,
    MT_CMD_ASSOCIATE = 0x03
} mt_cmd_t;

typedef enum {
    MT_PACKET_DATA = 0x00,
    MT_PACKET_RESERVED1 = 0x40,
    MT_PACKET_INIT = 0x80,
    MT_PACKET_RESERVED2 = 0xc0
} mt_udp_packet_class_t;

typedef struct {
    mt_addr_type_t type;
    uint8_t len;
    uint16_t port;
    uint8_t data[MT_MAX_ADDR_LEN];
} mt_addr_t;

typedef struct {
    mt_cmd_t cmd;
    mt_flow_protection_t flow_protection;
    mt_addr_t addr;
    const uint8_t *payload;
    size_t payload_len;
} mt_tcp_bootstrap_t;

typedef struct {
    mt_flow_protection_t flow_protection;
    uint8_t flow_id[MT_FLOW_ID_LEN];
    mt_addr_t addr;
    const uint8_t *payload;
    size_t payload_len;
} mt_udp_init_t;

typedef struct {
    uint8_t flow_id[MT_FLOW_ID_LEN];
    const uint8_t *payload;
    size_t payload_len;
} mt_udp_data_t;

typedef struct {
    mt_addr_t addr;
    const uint8_t *payload;
    size_t payload_len;
} mt_udp_stream_frame_t;

typedef struct {
    uint32_t epoch;
    uint8_t nonce[MT_KEY_NONCE_LEN];
    mt_cmd_t cmd;
    mt_flow_protection_t flow_protection;
    mt_addr_t addr;
    const uint8_t *payload;
    size_t payload_len;
} mt_key_tcp_bootstrap_t;

typedef struct {
    uint32_t epoch;
    uint8_t nonce[MT_KEY_NONCE_LEN];
    mt_flow_protection_t flow_protection;
    uint8_t flow_id[MT_FLOW_ID_LEN];
    mt_addr_t addr;
    const uint8_t *payload;
    size_t payload_len;
} mt_key_udp_init_t;

typedef int (*mt_key_seal_fn)(void *ctx,
                              const uint8_t nonce[MT_KEY_NONCE_LEN],
                              const uint8_t *plain, size_t plain_len,
                              uint8_t *ciphertext,
                              uint8_t tag[MT_KEY_TAG_LEN]);

typedef int (*mt_key_open_fn)(void *ctx,
                              const uint8_t nonce[MT_KEY_NONCE_LEN],
                              const uint8_t *ciphertext,
                              size_t ciphertext_len,
                              const uint8_t tag[MT_KEY_TAG_LEN],
                              uint8_t *plain);

typedef struct {
    void *ctx;
    mt_key_seal_fn seal;
    mt_key_open_fn open;
} mt_key_crypto_t;

mt_udp_packet_class_t mt_udp_packet_class(const uint8_t *src, size_t src_len);

void mt_flow_id_prepare(uint8_t flow_id[MT_FLOW_ID_LEN]);
int mt_flow_id_valid(const uint8_t flow_id[MT_FLOW_ID_LEN]);

void mt_key_udp_nonce_prepare(uint8_t nonce[MT_KEY_NONCE_LEN]);
int mt_key_udp_nonce_valid(const uint8_t nonce[MT_KEY_NONCE_LEN]);

size_t mt_tcp_bootstrap_header_size(mt_addr_type_t type, size_t addr_len);
size_t mt_tcp_bootstrap_size(mt_addr_type_t type, size_t addr_len,
                             size_t payload_len);

int mt_encode_tcp_bootstrap(uint8_t *dst, size_t dst_len,
                            mt_cmd_t cmd, mt_flow_protection_t flow_protection,
                            mt_addr_type_t type, const uint8_t *addr,
                            size_t addr_len, uint16_t port,
                            const uint8_t *payload, size_t payload_len,
                            size_t *written);

int mt_decode_tcp_bootstrap(const uint8_t *src, size_t src_len,
                            mt_tcp_bootstrap_t *bootstrap,
                            size_t *consumed);

size_t mt_udp_init_size(mt_addr_type_t type, size_t addr_len,
                        size_t payload_len);

int mt_encode_udp_init(uint8_t *dst, size_t dst_len,
                       mt_flow_protection_t flow_protection,
                       const uint8_t flow_id[MT_FLOW_ID_LEN],
                       mt_addr_type_t type, const uint8_t *addr,
                       size_t addr_len, uint16_t port,
                       const uint8_t *payload, size_t payload_len,
                       size_t *written);

int mt_decode_udp_init(const uint8_t *src, size_t src_len,
                       mt_udp_init_t *frame, size_t *consumed);

size_t mt_udp_data_size(size_t payload_len);

int mt_encode_udp_data(uint8_t *dst, size_t dst_len,
                       const uint8_t flow_id[MT_FLOW_ID_LEN],
                       const uint8_t *payload, size_t payload_len,
                       size_t *written);

int mt_decode_udp_data(const uint8_t *src, size_t src_len,
                       mt_udp_data_t *frame, size_t *consumed);

size_t mt_udp_stream_frame_size(mt_addr_type_t type, size_t addr_len,
                                size_t payload_len);

int mt_encode_udp_stream_frame(uint8_t *dst, size_t dst_len,
                               mt_addr_type_t type, const uint8_t *addr,
                               size_t addr_len, uint16_t port,
                               const uint8_t *payload, size_t payload_len,
                               size_t *written);

int mt_decode_udp_stream_frame(const uint8_t *src, size_t src_len,
                               mt_udp_stream_frame_t *frame,
                               size_t *consumed);

size_t mt_key_wire_size(size_t plain_len);

int mt_key_protect(uint8_t *dst, size_t dst_len,
                   const mt_key_crypto_t *crypto,
                   const uint8_t nonce[MT_KEY_NONCE_LEN],
                   const uint8_t *plain, size_t plain_len,
                   size_t *written);

int mt_key_unprotect(const uint8_t *src, size_t src_len,
                     const mt_key_crypto_t *crypto,
                     uint8_t *plain, size_t plain_len,
                     uint8_t nonce[MT_KEY_NONCE_LEN],
                     size_t *plain_written);

size_t mt_key_tcp_bootstrap_size(mt_addr_type_t type, size_t addr_len,
                                 size_t payload_len);

int mt_encode_key_tcp_bootstrap(uint8_t *dst, size_t dst_len,
                                const mt_key_crypto_t *crypto,
                                const uint8_t nonce[MT_KEY_NONCE_LEN],
                                uint32_t epoch, mt_cmd_t cmd,
                                mt_flow_protection_t flow_protection,
                                mt_addr_type_t type, const uint8_t *addr,
                                size_t addr_len, uint16_t port,
                                const uint8_t *payload, size_t payload_len,
                                size_t *written);

int mt_decode_key_tcp_bootstrap(const uint8_t *src, size_t src_len,
                                const mt_key_crypto_t *crypto,
                                uint8_t *plain, size_t plain_len,
                                mt_key_tcp_bootstrap_t *bootstrap,
                                size_t *consumed);

size_t mt_key_udp_init_size(mt_addr_type_t type, size_t addr_len,
                            size_t payload_len);

int mt_encode_key_udp_init(uint8_t *dst, size_t dst_len,
                           const mt_key_crypto_t *crypto,
                           const uint8_t nonce[MT_KEY_NONCE_LEN],
                           uint32_t epoch, mt_flow_protection_t flow_protection,
                           const uint8_t flow_id[MT_FLOW_ID_LEN],
                           mt_addr_type_t type, const uint8_t *addr,
                           size_t addr_len, uint16_t port,
                           const uint8_t *payload, size_t payload_len,
                           size_t *written);

int mt_decode_key_udp_init(const uint8_t *src, size_t src_len,
                           const mt_key_crypto_t *crypto,
                           uint8_t *plain, size_t plain_len,
                           mt_key_udp_init_t *frame, size_t *consumed);

#ifdef __cplusplus
}
#endif

#endif

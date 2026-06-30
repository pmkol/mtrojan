#include "mtrojan.h"

#include <stdlib.h>
#include <string.h>

#define MT_TCP_BASE_LEN 6
#define MT_UDP_INIT_BASE_LEN (1 + MT_FLOW_ID_LEN + 4)
#define MT_UDP_DATA_BASE_LEN MT_FLOW_ID_LEN
#define MT_UDP_STREAM_LEN_PREFIX 2
#define MT_UDP_STREAM_BASE_LEN (MT_UDP_STREAM_LEN_PREFIX + 4)
#define MT_KEY_EPOCH_LEN 4

static int
mt_valid_flow_protection(mt_flow_protection_t mode)
{
    return mode == MT_PROTECT_BOOTSTRAP
           || mode == MT_PROTECT_HANDSHAKE
           || mode == MT_PROTECT_FULL;
}

static int
mt_valid_no_key_flow_protection(mt_flow_protection_t mode)
{
    return mode == MT_PROTECT_BOOTSTRAP;
}

static int
mt_valid_cmd(mt_cmd_t cmd)
{
    return cmd == MT_CMD_CONNECT || cmd == MT_CMD_ASSOCIATE;
}

static int
mt_valid_addr(mt_addr_type_t type, size_t addr_len)
{
    switch (type) {
    case MT_ADDR_IPV4:
        return addr_len == 4;
    case MT_ADDR_IPV6:
        return addr_len == 16;
    case MT_ADDR_DOMAIN:
        return addr_len > 0 && addr_len <= MT_MAX_ADDR_LEN;
    default:
        return 0;
    }
}

static void
mt_write_u16(uint8_t *dst, uint16_t value)
{
    dst[0] = (uint8_t) (value >> 8);
    dst[1] = (uint8_t) value;
}

static void
mt_write_u32(uint8_t *dst, uint32_t value)
{
    dst[0] = (uint8_t) (value >> 24);
    dst[1] = (uint8_t) (value >> 16);
    dst[2] = (uint8_t) (value >> 8);
    dst[3] = (uint8_t) value;
}

static uint16_t
mt_read_u16(const uint8_t *src)
{
    return (uint16_t) (((uint16_t) src[0] << 8) | src[1]);
}

static uint32_t
mt_read_u32(const uint8_t *src)
{
    return ((uint32_t) src[0] << 24)
           | ((uint32_t) src[1] << 16)
           | ((uint32_t) src[2] << 8)
           | (uint32_t) src[3];
}

static size_t
mt_addr_header_size(mt_addr_type_t type, size_t addr_len)
{
    if (!mt_valid_addr(type, addr_len)) {
        return 0;
    }

    return 1 + 1 + addr_len + 2;
}

static int
mt_write_addr(uint8_t *dst, size_t dst_len, mt_addr_type_t type,
              const uint8_t *addr, size_t addr_len, uint16_t port,
              size_t *written)
{
    size_t need;

    if (dst == NULL || addr == NULL || written == NULL
        || !mt_valid_addr(type, addr_len))
    {
        return MT_ERR_INVALID;
    }

    need = mt_addr_header_size(type, addr_len);
    if (dst_len < need) {
        return MT_ERR_NO_SPACE;
    }

    dst[0] = (uint8_t) type;
    dst[1] = (uint8_t) addr_len;
    memcpy(&dst[2], addr, addr_len);
    mt_write_u16(&dst[2 + addr_len], port);

    *written = need;
    return MT_OK;
}

static int
mt_read_addr(const uint8_t *src, size_t src_len, mt_addr_t *addr,
             size_t *consumed)
{
    mt_addr_type_t type;
    size_t addr_len;
    size_t need;

    if (src == NULL || addr == NULL || consumed == NULL) {
        return MT_ERR_INVALID;
    }

    if (src_len < 4) {
        return MT_ERR_AGAIN;
    }

    type = (mt_addr_type_t) src[0];
    addr_len = src[1];
    if (!mt_valid_addr(type, addr_len)) {
        return MT_ERR_INVALID;
    }

    need = mt_addr_header_size(type, addr_len);
    if (src_len < need) {
        return MT_ERR_AGAIN;
    }

    memset(addr, 0, sizeof(*addr));
    addr->type = type;
    addr->len = (uint8_t) addr_len;
    memcpy(addr->data, &src[2], addr_len);
    addr->port = mt_read_u16(&src[2 + addr_len]);

    *consumed = need;
    return MT_OK;
}

static int
mt_payload_valid(const uint8_t *payload, size_t payload_len)
{
    return payload_len == 0 || payload != NULL;
}

mt_udp_packet_class_t
mt_udp_packet_class(const uint8_t *src, size_t src_len)
{
    if (src == NULL || src_len == 0) {
        return MT_PACKET_RESERVED2;
    }

    return (mt_udp_packet_class_t) (src[0] & 0xc0);
}

void
mt_flow_id_prepare(uint8_t flow_id[MT_FLOW_ID_LEN])
{
    if (flow_id != NULL) {
        flow_id[0] &= 0x3f;
    }
}

int
mt_flow_id_valid(const uint8_t flow_id[MT_FLOW_ID_LEN])
{
    return flow_id != NULL && (flow_id[0] & 0xc0) == MT_PACKET_DATA;
}

void
mt_key_udp_nonce_prepare(uint8_t nonce[MT_KEY_NONCE_LEN])
{
    if (nonce != NULL) {
        nonce[0] = (uint8_t) ((nonce[0] & 0x3f) | MT_PACKET_INIT);
    }
}

int
mt_key_udp_nonce_valid(const uint8_t nonce[MT_KEY_NONCE_LEN])
{
    return nonce != NULL && (nonce[0] & 0xc0) == MT_PACKET_INIT;
}

size_t
mt_tcp_bootstrap_header_size(mt_addr_type_t type, size_t addr_len)
{
    if (!mt_valid_addr(type, addr_len)) {
        return 0;
    }

    return 2 + mt_addr_header_size(type, addr_len);
}

size_t
mt_tcp_bootstrap_size(mt_addr_type_t type, size_t addr_len,
                      size_t payload_len)
{
    size_t header = mt_tcp_bootstrap_header_size(type, addr_len);

    if (header == 0 || payload_len > MT_BOOTSTRAP_PAYLOAD_MAX) {
        return 0;
    }

    return header + payload_len;
}

static int
mt_encode_tcp_bootstrap_impl(uint8_t *dst, size_t dst_len,
                             mt_cmd_t cmd, mt_flow_protection_t flow_protection,
                             mt_addr_type_t type, const uint8_t *addr,
                             size_t addr_len, uint16_t port,
                             const uint8_t *payload, size_t payload_len,
                             size_t *written, int key_mode)
{
    size_t addr_written;
    size_t need;
    int rc;

    if (dst == NULL || written == NULL
        || !mt_valid_cmd(cmd)
        || !(key_mode ? mt_valid_flow_protection(flow_protection)
                      : mt_valid_no_key_flow_protection(flow_protection))
        || !mt_payload_valid(payload, payload_len))
    {
        return MT_ERR_INVALID;
    }

    need = mt_tcp_bootstrap_size(type, addr_len, payload_len);
    if (need == 0) {
        return MT_ERR_INVALID;
    }

    if (dst_len < need) {
        return MT_ERR_NO_SPACE;
    }

    dst[0] = (uint8_t) cmd;
    dst[1] = (uint8_t) flow_protection;
    rc = mt_write_addr(&dst[2], dst_len - 2, type, addr, addr_len, port,
                       &addr_written);
    if (rc != MT_OK) {
        return rc;
    }

    if (payload_len != 0) {
        memcpy(&dst[2 + addr_written], payload, payload_len);
    }

    *written = need;
    return MT_OK;
}

int
mt_encode_tcp_bootstrap(uint8_t *dst, size_t dst_len,
                        mt_cmd_t cmd, mt_flow_protection_t flow_protection,
                        mt_addr_type_t type, const uint8_t *addr,
                        size_t addr_len, uint16_t port,
                        const uint8_t *payload, size_t payload_len,
                        size_t *written)
{
    return mt_encode_tcp_bootstrap_impl(dst, dst_len, cmd, flow_protection,
                                        type, addr, addr_len, port, payload,
                                        payload_len, written, 0);
}

static int
mt_decode_tcp_bootstrap_impl(const uint8_t *src, size_t src_len,
                             mt_tcp_bootstrap_t *bootstrap, size_t *consumed,
                             int key_mode)
{
    size_t addr_consumed;
    mt_cmd_t cmd;
    mt_flow_protection_t flow_protection;
    int rc;

    if (src == NULL || bootstrap == NULL || consumed == NULL) {
        return MT_ERR_INVALID;
    }

    if (src_len < MT_TCP_BASE_LEN) {
        return MT_ERR_AGAIN;
    }

    cmd = (mt_cmd_t) src[0];
    if (!mt_valid_cmd(cmd)) {
        return MT_ERR_INVALID;
    }

    flow_protection = (mt_flow_protection_t) src[1];
    if (!(key_mode ? mt_valid_flow_protection(flow_protection)
                   : mt_valid_no_key_flow_protection(flow_protection)))
    {
        return MT_ERR_INVALID;
    }

    memset(bootstrap, 0, sizeof(*bootstrap));
    rc = mt_read_addr(&src[2], src_len - 2, &bootstrap->addr,
                      &addr_consumed);
    if (rc != MT_OK) {
        return rc;
    }

    bootstrap->cmd = cmd;
    bootstrap->flow_protection = flow_protection;
    bootstrap->payload = &src[2 + addr_consumed];
    bootstrap->payload_len = src_len - 2 - addr_consumed;
    *consumed = 2 + addr_consumed;

    return MT_OK;
}

int
mt_decode_tcp_bootstrap(const uint8_t *src, size_t src_len,
                        mt_tcp_bootstrap_t *bootstrap, size_t *consumed)
{
    return mt_decode_tcp_bootstrap_impl(src, src_len, bootstrap, consumed, 0);
}

size_t
mt_udp_init_size(mt_addr_type_t type, size_t addr_len, size_t payload_len)
{
    size_t addr_header = mt_addr_header_size(type, addr_len);

    if (addr_header == 0 || payload_len > MT_BOOTSTRAP_PAYLOAD_MAX) {
        return 0;
    }

    return 1 + MT_FLOW_ID_LEN + addr_header + payload_len;
}

int
mt_encode_udp_init(uint8_t *dst, size_t dst_len,
                   mt_flow_protection_t flow_protection,
                   const uint8_t flow_id[MT_FLOW_ID_LEN],
                   mt_addr_type_t type, const uint8_t *addr,
                   size_t addr_len, uint16_t port,
                   const uint8_t *payload, size_t payload_len,
                   size_t *written)
{
    size_t addr_written;
    size_t need;
    int rc;

    if (dst == NULL || written == NULL
        || !mt_valid_no_key_flow_protection(flow_protection)
        || !mt_flow_id_valid(flow_id) || !mt_payload_valid(payload, payload_len))
    {
        return MT_ERR_INVALID;
    }

    need = mt_udp_init_size(type, addr_len, payload_len);
    if (need == 0) {
        return MT_ERR_INVALID;
    }

    if (dst_len < need) {
        return MT_ERR_NO_SPACE;
    }

    dst[0] = (uint8_t) (MT_PACKET_INIT | ((uint8_t) flow_protection & 0x3f));
    memcpy(&dst[1], flow_id, MT_FLOW_ID_LEN);
    rc = mt_write_addr(&dst[1 + MT_FLOW_ID_LEN],
                       dst_len - 1 - MT_FLOW_ID_LEN, type, addr, addr_len,
                       port, &addr_written);
    if (rc != MT_OK) {
        return rc;
    }

    if (payload_len != 0) {
        memcpy(&dst[1 + MT_FLOW_ID_LEN + addr_written], payload, payload_len);
    }

    *written = need;
    return MT_OK;
}

int
mt_decode_udp_init(const uint8_t *src, size_t src_len, mt_udp_init_t *frame,
                   size_t *consumed)
{
    size_t addr_consumed;
    mt_flow_protection_t flow_protection;
    int rc;

    if (src == NULL || frame == NULL || consumed == NULL) {
        return MT_ERR_INVALID;
    }

    if (src_len < MT_UDP_INIT_BASE_LEN) {
        return MT_ERR_AGAIN;
    }

    if (mt_udp_packet_class(src, src_len) != MT_PACKET_INIT) {
        return MT_ERR_INVALID;
    }

    flow_protection = (mt_flow_protection_t) (src[0] & 0x3f);
    if (!mt_valid_no_key_flow_protection(flow_protection)) {
        return MT_ERR_INVALID;
    }

    if (!mt_flow_id_valid(&src[1])) {
        return MT_ERR_INVALID;
    }

    memset(frame, 0, sizeof(*frame));
    memcpy(frame->flow_id, &src[1], MT_FLOW_ID_LEN);
    rc = mt_read_addr(&src[1 + MT_FLOW_ID_LEN],
                      src_len - 1 - MT_FLOW_ID_LEN, &frame->addr,
                      &addr_consumed);
    if (rc != MT_OK) {
        return rc;
    }

    frame->flow_protection = flow_protection;
    frame->payload = &src[1 + MT_FLOW_ID_LEN + addr_consumed];
    frame->payload_len = src_len - 1 - MT_FLOW_ID_LEN - addr_consumed;
    *consumed = 1 + MT_FLOW_ID_LEN + addr_consumed;

    return MT_OK;
}

size_t
mt_udp_data_size(size_t payload_len)
{
    return MT_FLOW_ID_LEN + payload_len;
}

int
mt_encode_udp_data(uint8_t *dst, size_t dst_len,
                   const uint8_t flow_id[MT_FLOW_ID_LEN],
                   const uint8_t *payload, size_t payload_len,
                   size_t *written)
{
    size_t need;

    if (dst == NULL || written == NULL || !mt_flow_id_valid(flow_id)
        || !mt_payload_valid(payload, payload_len))
    {
        return MT_ERR_INVALID;
    }

    need = mt_udp_data_size(payload_len);
    if (dst_len < need) {
        return MT_ERR_NO_SPACE;
    }

    memcpy(dst, flow_id, MT_FLOW_ID_LEN);
    if (payload_len != 0) {
        memcpy(&dst[MT_FLOW_ID_LEN], payload, payload_len);
    }

    *written = need;
    return MT_OK;
}

int
mt_decode_udp_data(const uint8_t *src, size_t src_len, mt_udp_data_t *frame,
                   size_t *consumed)
{
    if (src == NULL || frame == NULL || consumed == NULL) {
        return MT_ERR_INVALID;
    }

    if (src_len < MT_UDP_DATA_BASE_LEN) {
        return MT_ERR_AGAIN;
    }

    if (mt_udp_packet_class(src, src_len) != MT_PACKET_DATA) {
        return MT_ERR_INVALID;
    }

    memset(frame, 0, sizeof(*frame));
    memcpy(frame->flow_id, src, MT_FLOW_ID_LEN);
    frame->payload = &src[MT_FLOW_ID_LEN];
    frame->payload_len = src_len - MT_FLOW_ID_LEN;
    *consumed = src_len;

    return MT_OK;
}

size_t
mt_udp_stream_frame_size(mt_addr_type_t type, size_t addr_len,
                         size_t payload_len)
{
    size_t addr_header;
    size_t frame_len;

    addr_header = mt_addr_header_size(type, addr_len);
    if (addr_header == 0) {
        return 0;
    }

    frame_len = addr_header + payload_len;
    if (frame_len > UINT16_MAX) {
        return 0;
    }

    return MT_UDP_STREAM_LEN_PREFIX + frame_len;
}

int
mt_encode_udp_stream_frame(uint8_t *dst, size_t dst_len,
                           mt_addr_type_t type, const uint8_t *addr,
                           size_t addr_len, uint16_t port,
                           const uint8_t *payload, size_t payload_len,
                           size_t *written)
{
    size_t addr_written;
    size_t need;
    size_t frame_len;
    int rc;

    if (dst == NULL || written == NULL
        || !mt_payload_valid(payload, payload_len))
    {
        return MT_ERR_INVALID;
    }

    need = mt_udp_stream_frame_size(type, addr_len, payload_len);
    if (need == 0) {
        return MT_ERR_INVALID;
    }

    if (dst_len < need) {
        return MT_ERR_NO_SPACE;
    }

    frame_len = need - MT_UDP_STREAM_LEN_PREFIX;
    mt_write_u16(dst, (uint16_t) frame_len);
    rc = mt_write_addr(&dst[MT_UDP_STREAM_LEN_PREFIX],
                       dst_len - MT_UDP_STREAM_LEN_PREFIX, type, addr,
                       addr_len, port, &addr_written);
    if (rc != MT_OK) {
        return rc;
    }

    if (payload_len != 0) {
        memcpy(&dst[MT_UDP_STREAM_LEN_PREFIX + addr_written], payload,
               payload_len);
    }

    *written = need;
    return MT_OK;
}

int
mt_decode_udp_stream_frame(const uint8_t *src, size_t src_len,
                           mt_udp_stream_frame_t *frame, size_t *consumed)
{
    uint16_t frame_len;
    size_t addr_consumed;
    size_t need;
    int rc;

    if (src == NULL || frame == NULL || consumed == NULL) {
        return MT_ERR_INVALID;
    }

    if (src_len < MT_UDP_STREAM_LEN_PREFIX) {
        return MT_ERR_AGAIN;
    }

    frame_len = mt_read_u16(src);
    need = MT_UDP_STREAM_LEN_PREFIX + frame_len;
    if (src_len < need) {
        return MT_ERR_AGAIN;
    }

    memset(frame, 0, sizeof(*frame));
    rc = mt_read_addr(&src[MT_UDP_STREAM_LEN_PREFIX], frame_len,
                      &frame->addr, &addr_consumed);
    if (rc != MT_OK) {
        return rc;
    }

    frame->payload = &src[MT_UDP_STREAM_LEN_PREFIX + addr_consumed];
    frame->payload_len = frame_len - addr_consumed;
    *consumed = need;

    return MT_OK;
}

static void
mt_cleanse(void *ptr, size_t len)
{
    volatile uint8_t *p = (volatile uint8_t *) ptr;

    while (len-- != 0) {
        *p++ = 0;
    }
}

static int
mt_key_crypto_valid(const mt_key_crypto_t *crypto)
{
    return crypto != NULL && crypto->seal != NULL && crypto->open != NULL;
}

size_t
mt_key_wire_size(size_t plain_len)
{
    if (plain_len > MT_KEY_PLAIN_MAX) {
        return 0;
    }

    return MT_KEY_NONCE_LEN + plain_len + MT_KEY_TAG_LEN;
}

int
mt_key_protect(uint8_t *dst, size_t dst_len,
               const mt_key_crypto_t *crypto,
               const uint8_t nonce[MT_KEY_NONCE_LEN],
               const uint8_t *plain, size_t plain_len, size_t *written)
{
    size_t need;
    int rc;

    if (dst == NULL || written == NULL || nonce == NULL
        || !mt_key_crypto_valid(crypto)
        || !mt_payload_valid(plain, plain_len))
    {
        return MT_ERR_INVALID;
    }

    need = mt_key_wire_size(plain_len);
    if (need == 0) {
        return MT_ERR_INVALID;
    }

    if (dst_len < need) {
        return MT_ERR_NO_SPACE;
    }

    memcpy(dst, nonce, MT_KEY_NONCE_LEN);
    rc = crypto->seal(crypto->ctx, nonce, plain, plain_len,
                      &dst[MT_KEY_NONCE_LEN],
                      &dst[MT_KEY_NONCE_LEN + plain_len]);
    if (rc != MT_OK) {
        mt_cleanse(&dst[MT_KEY_NONCE_LEN], plain_len + MT_KEY_TAG_LEN);
        return MT_ERR_INVALID;
    }

    *written = need;
    return MT_OK;
}

int
mt_key_unprotect(const uint8_t *src, size_t src_len,
                 const mt_key_crypto_t *crypto,
                 uint8_t *plain, size_t plain_len,
                 uint8_t nonce[MT_KEY_NONCE_LEN], size_t *plain_written)
{
    const uint8_t *ciphertext;
    const uint8_t *tag;
    size_t ciphertext_len;
    int rc;

    if (src == NULL || plain == NULL || nonce == NULL || plain_written == NULL
        || !mt_key_crypto_valid(crypto))
    {
        return MT_ERR_INVALID;
    }

    if (src_len < MT_KEY_NONCE_LEN + MT_KEY_TAG_LEN) {
        return MT_ERR_AGAIN;
    }

    ciphertext_len = src_len - MT_KEY_NONCE_LEN - MT_KEY_TAG_LEN;
    if (ciphertext_len > MT_KEY_PLAIN_MAX) {
        return MT_ERR_INVALID;
    }

    if (ciphertext_len > plain_len) {
        return MT_ERR_NO_SPACE;
    }

    memcpy(nonce, src, MT_KEY_NONCE_LEN);
    ciphertext = &src[MT_KEY_NONCE_LEN];
    tag = &src[MT_KEY_NONCE_LEN + ciphertext_len];

    rc = crypto->open(crypto->ctx, nonce, ciphertext, ciphertext_len, tag,
                      plain);
    if (rc != MT_OK) {
        mt_cleanse(plain, ciphertext_len);
        return MT_ERR_INVALID;
    }

    *plain_written = ciphertext_len;
    return MT_OK;
}

static size_t
mt_key_tcp_plain_size(mt_addr_type_t type, size_t addr_len,
                      size_t payload_len)
{
    size_t tcp_size = mt_tcp_bootstrap_size(type, addr_len, payload_len);

    if (tcp_size == 0) {
        return 0;
    }

    return MT_KEY_EPOCH_LEN + tcp_size;
}

size_t
mt_key_tcp_bootstrap_size(mt_addr_type_t type, size_t addr_len,
                          size_t payload_len)
{
    size_t plain_len = mt_key_tcp_plain_size(type, addr_len, payload_len);

    if (plain_len == 0) {
        return 0;
    }

    return MT_KEY_NONCE_LEN + MT_KEY_TCP_LEN_LEN + plain_len + MT_KEY_TAG_LEN;
}

static int
mt_key_tcp_protect(uint8_t *dst, size_t dst_len,
                   const mt_key_crypto_t *crypto,
                   const uint8_t nonce[MT_KEY_NONCE_LEN],
                   const uint8_t *plain, size_t plain_len, size_t *written)
{
    size_t need;
    int rc;

    if (dst == NULL || written == NULL || nonce == NULL
        || !mt_key_crypto_valid(crypto)
        || !mt_payload_valid(plain, plain_len))
    {
        return MT_ERR_INVALID;
    }

    if (plain_len > MT_KEY_PLAIN_MAX || plain_len > UINT16_MAX) {
        return MT_ERR_INVALID;
    }

    need = MT_KEY_NONCE_LEN + MT_KEY_TCP_LEN_LEN + plain_len + MT_KEY_TAG_LEN;
    if (dst_len < need) {
        return MT_ERR_NO_SPACE;
    }

    memcpy(dst, nonce, MT_KEY_NONCE_LEN);
    mt_write_u16(&dst[MT_KEY_NONCE_LEN], (uint16_t) plain_len);
    rc = crypto->seal(crypto->ctx, nonce, plain, plain_len,
                      &dst[MT_KEY_NONCE_LEN + MT_KEY_TCP_LEN_LEN],
                      &dst[MT_KEY_NONCE_LEN + MT_KEY_TCP_LEN_LEN
                           + plain_len]);
    if (rc != MT_OK) {
        mt_cleanse(&dst[MT_KEY_NONCE_LEN + MT_KEY_TCP_LEN_LEN],
                   plain_len + MT_KEY_TAG_LEN);
        return MT_ERR_INVALID;
    }

    *written = need;
    return MT_OK;
}

static int
mt_key_tcp_unprotect(const uint8_t *src, size_t src_len,
                     const mt_key_crypto_t *crypto, uint8_t *plain,
                     size_t plain_len, uint8_t nonce[MT_KEY_NONCE_LEN],
                     size_t *plain_written, size_t *consumed)
{
    const uint8_t *ciphertext;
    const uint8_t *tag;
    size_t ciphertext_len, need;
    int rc;

    if (src == NULL || plain == NULL || nonce == NULL
        || plain_written == NULL || consumed == NULL
        || !mt_key_crypto_valid(crypto))
    {
        return MT_ERR_INVALID;
    }

    if (src_len < MT_KEY_NONCE_LEN + MT_KEY_TCP_LEN_LEN) {
        return MT_ERR_AGAIN;
    }

    ciphertext_len = mt_read_u16(&src[MT_KEY_NONCE_LEN]);
    if (ciphertext_len > MT_KEY_PLAIN_MAX) {
        return MT_ERR_INVALID;
    }

    need = MT_KEY_NONCE_LEN + MT_KEY_TCP_LEN_LEN + ciphertext_len
           + MT_KEY_TAG_LEN;
    if (src_len < need) {
        return MT_ERR_AGAIN;
    }

    if (ciphertext_len > plain_len) {
        return MT_ERR_NO_SPACE;
    }

    memcpy(nonce, src, MT_KEY_NONCE_LEN);
    ciphertext = &src[MT_KEY_NONCE_LEN + MT_KEY_TCP_LEN_LEN];
    tag = &src[MT_KEY_NONCE_LEN + MT_KEY_TCP_LEN_LEN + ciphertext_len];

    rc = crypto->open(crypto->ctx, nonce, ciphertext, ciphertext_len, tag,
                      plain);
    if (rc != MT_OK) {
        mt_cleanse(plain, ciphertext_len);
        return MT_ERR_INVALID;
    }

    *plain_written = ciphertext_len;
    *consumed = need;
    return MT_OK;
}

int
mt_encode_key_tcp_bootstrap(uint8_t *dst, size_t dst_len,
                            const mt_key_crypto_t *crypto,
                            const uint8_t nonce[MT_KEY_NONCE_LEN],
                            uint32_t epoch, mt_cmd_t cmd,
                            mt_flow_protection_t flow_protection,
                            mt_addr_type_t type, const uint8_t *addr,
                            size_t addr_len, uint16_t port,
                            const uint8_t *payload, size_t payload_len,
                            size_t *written)
{
    uint8_t *plain = NULL;
    size_t plain_len;
    size_t tcp_written;
    int rc;

    if (written == NULL || !mt_valid_cmd(cmd)) {
        return MT_ERR_INVALID;
    }

    plain_len = mt_key_tcp_plain_size(type, addr_len, payload_len);
    if (plain_len == 0) {
        return MT_ERR_INVALID;
    }

    plain = (uint8_t *) malloc(plain_len);
    if (plain == NULL) {
        return MT_ERR_INVALID;
    }

    mt_write_u32(plain, epoch);
    rc = mt_encode_tcp_bootstrap_impl(&plain[MT_KEY_EPOCH_LEN],
                                      plain_len - MT_KEY_EPOCH_LEN, cmd,
                                      flow_protection, type, addr, addr_len,
                                      port, payload, payload_len, &tcp_written,
                                      1);
    if (rc == MT_OK) {
        rc = mt_key_tcp_protect(dst, dst_len, crypto, nonce, plain,
                                MT_KEY_EPOCH_LEN + tcp_written, written);
    }

    mt_cleanse(plain, plain_len);
    free(plain);
    return rc;
}

int
mt_decode_key_tcp_bootstrap(const uint8_t *src, size_t src_len,
                            const mt_key_crypto_t *crypto,
                            uint8_t *plain, size_t plain_len,
                            mt_key_tcp_bootstrap_t *bootstrap,
                            size_t *consumed)
{
    mt_tcp_bootstrap_t tcp;
    uint8_t nonce[MT_KEY_NONCE_LEN];
    size_t plain_written;
    size_t tcp_consumed;
    size_t wire_consumed;
    int rc;

    if (bootstrap == NULL || consumed == NULL) {
        return MT_ERR_INVALID;
    }

    rc = mt_key_tcp_unprotect(src, src_len, crypto, plain, plain_len, nonce,
                              &plain_written, &wire_consumed);
    if (rc != MT_OK) {
        return rc;
    }

    if (plain_written < MT_KEY_EPOCH_LEN + MT_TCP_BASE_LEN) {
        return MT_ERR_INVALID;
    }

    rc = mt_decode_tcp_bootstrap_impl(&plain[MT_KEY_EPOCH_LEN],
                                      plain_written - MT_KEY_EPOCH_LEN, &tcp,
                                      &tcp_consumed, 1);
    if (rc != MT_OK) {
        return rc;
    }

    memset(bootstrap, 0, sizeof(*bootstrap));
    bootstrap->epoch = mt_read_u32(plain);
    memcpy(bootstrap->nonce, nonce, MT_KEY_NONCE_LEN);
    bootstrap->cmd = tcp.cmd;
    bootstrap->flow_protection = tcp.flow_protection;
    bootstrap->addr = tcp.addr;
    bootstrap->payload = tcp.payload;
    bootstrap->payload_len = tcp.payload_len;
    *consumed = wire_consumed;

    return MT_OK;
}

static size_t
mt_key_udp_init_plain_size(mt_addr_type_t type, size_t addr_len,
                           size_t payload_len)
{
    size_t addr_header = mt_addr_header_size(type, addr_len);

    if (addr_header == 0 || payload_len > MT_BOOTSTRAP_PAYLOAD_MAX) {
        return 0;
    }

    return MT_KEY_EPOCH_LEN + 1 + MT_FLOW_ID_LEN + addr_header + payload_len;
}

size_t
mt_key_udp_init_size(mt_addr_type_t type, size_t addr_len, size_t payload_len)
{
    size_t plain_len = mt_key_udp_init_plain_size(type, addr_len, payload_len);

    if (plain_len == 0) {
        return 0;
    }

    return mt_key_wire_size(plain_len);
}

int
mt_encode_key_udp_init(uint8_t *dst, size_t dst_len,
                       const mt_key_crypto_t *crypto,
                       const uint8_t nonce[MT_KEY_NONCE_LEN], uint32_t epoch,
                       mt_flow_protection_t flow_protection,
                       const uint8_t flow_id[MT_FLOW_ID_LEN],
                       mt_addr_type_t type, const uint8_t *addr,
                       size_t addr_len, uint16_t port,
                       const uint8_t *payload, size_t payload_len,
                       size_t *written)
{
    uint8_t *plain = NULL;
    uint8_t wire_nonce[MT_KEY_NONCE_LEN];
    size_t plain_len;
    size_t addr_written;
    size_t off;
    int rc = MT_ERR_INVALID;

    if (nonce == NULL || written == NULL || !mt_valid_flow_protection(flow_protection)
        || !mt_flow_id_valid(flow_id)
        || !mt_payload_valid(payload, payload_len))
    {
        return MT_ERR_INVALID;
    }

    plain_len = mt_key_udp_init_plain_size(type, addr_len, payload_len);
    if (plain_len == 0) {
        return MT_ERR_INVALID;
    }

    plain = (uint8_t *) malloc(plain_len);
    if (plain == NULL) {
        return MT_ERR_INVALID;
    }

    off = 0;
    mt_write_u32(&plain[off], epoch);
    off += MT_KEY_EPOCH_LEN;
    plain[off++] = (uint8_t) flow_protection;
    memcpy(&plain[off], flow_id, MT_FLOW_ID_LEN);
    off += MT_FLOW_ID_LEN;
    rc = mt_write_addr(&plain[off], plain_len - off, type, addr, addr_len,
                       port, &addr_written);
    if (rc != MT_OK) {
        goto done;
    }
    off += addr_written;
    if (payload_len != 0) {
        memcpy(&plain[off], payload, payload_len);
    }

    memcpy(wire_nonce, nonce, MT_KEY_NONCE_LEN);
    mt_key_udp_nonce_prepare(wire_nonce);
    rc = mt_key_protect(dst, dst_len, crypto, wire_nonce, plain, plain_len,
                        written);

done:
    mt_cleanse(plain, plain_len);
    free(plain);
    return rc;
}

int
mt_decode_key_udp_init(const uint8_t *src, size_t src_len,
                       const mt_key_crypto_t *crypto, uint8_t *plain,
                       size_t plain_len, mt_key_udp_init_t *frame,
                       size_t *consumed)
{
    uint8_t nonce[MT_KEY_NONCE_LEN];
    size_t plain_written;
    size_t addr_consumed;
    mt_flow_protection_t flow_protection;
    size_t off;
    int rc;

    if (src == NULL || frame == NULL || consumed == NULL) {
        return MT_ERR_INVALID;
    }

    if (src_len < MT_KEY_NONCE_LEN + MT_KEY_TAG_LEN) {
        return MT_ERR_AGAIN;
    }

    if (!mt_key_udp_nonce_valid(src)) {
        return MT_ERR_INVALID;
    }

    rc = mt_key_unprotect(src, src_len, crypto, plain, plain_len, nonce,
                          &plain_written);
    if (rc != MT_OK) {
        return rc;
    }

    if (plain_written < MT_KEY_EPOCH_LEN + 1 + MT_FLOW_ID_LEN + 4) {
        return MT_ERR_INVALID;
    }

    off = MT_KEY_EPOCH_LEN;
    flow_protection = (mt_flow_protection_t) plain[off++];
    if (!mt_valid_flow_protection(flow_protection)) {
        return MT_ERR_INVALID;
    }

    if (!mt_flow_id_valid(&plain[off])) {
        return MT_ERR_INVALID;
    }

    memset(frame, 0, sizeof(*frame));
    frame->epoch = mt_read_u32(plain);
    memcpy(frame->nonce, nonce, MT_KEY_NONCE_LEN);
    frame->flow_protection = flow_protection;
    memcpy(frame->flow_id, &plain[off], MT_FLOW_ID_LEN);
    off += MT_FLOW_ID_LEN;

    rc = mt_read_addr(&plain[off], plain_written - off, &frame->addr,
                      &addr_consumed);
    if (rc != MT_OK) {
        return rc;
    }

    off += addr_consumed;
    frame->payload = &plain[off];
    frame->payload_len = plain_written - off;
    *consumed = src_len;

    return MT_OK;
}

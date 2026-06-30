#include "mtrojan.h"

#include <assert.h>
#include <ctype.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    uint8_t key;
} test_crypto_ctx_t;

typedef struct {
    const uint8_t *nonce;
    size_t nonce_len;
    const uint8_t *plain;
    size_t plain_len;
    const uint8_t *ciphertext;
    size_t ciphertext_len;
    const uint8_t *tag;
} vector_crypto_ctx_t;

static int
hex_value(int c)
{
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    }
    if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    }
    return -1;
}

static size_t
hex_to_bytes(const char *hex, uint8_t *dst, size_t dst_len)
{
    size_t n = 0;

    assert(hex != NULL);
    assert(dst != NULL);

    while (*hex != '\0') {
        int hi, lo;

        while (isspace((unsigned char) *hex)) {
            hex++;
        }
        if (*hex == '\0') {
            break;
        }

        hi = hex_value((unsigned char) hex[0]);
        lo = hex_value((unsigned char) hex[1]);
        assert(hi >= 0 && lo >= 0);
        assert(n < dst_len);
        dst[n++] = (uint8_t) ((hi << 4) | lo);
        hex += 2;
    }

    return n;
}

static void
assert_hex_eq(const uint8_t *actual, size_t actual_len, const char *hex)
{
    uint8_t expected[512];
    size_t expected_len;

    expected_len = hex_to_bytes(hex, expected, sizeof(expected));
    assert(actual_len == expected_len);
    assert(memcmp(actual, expected, expected_len) == 0);
}

static void
assert_readme_contains(const char *needle)
{
    FILE *f;
    char *buf;
    long size;
    size_t n;

    f = fopen("README.md", "rb");
    assert(f != NULL);
    assert(fseek(f, 0, SEEK_END) == 0);
    size = ftell(f);
    assert(size >= 0);
    assert(fseek(f, 0, SEEK_SET) == 0);
    buf = (char *) malloc((size_t) size + 1);
    assert(buf != NULL);
    n = fread(buf, 1, (size_t) size, f);
    assert(n == (size_t) size);
    buf[n] = '\0';
    assert(strstr(buf, needle) != NULL);
    free(buf);
    assert(fclose(f) == 0);
}

static uint8_t
test_mask(const test_crypto_ctx_t *ctx, const uint8_t nonce[MT_KEY_NONCE_LEN],
          size_t i)
{
    return (uint8_t) (ctx->key ^ nonce[i % MT_KEY_NONCE_LEN] ^ (uint8_t) i);
}

static void
test_tag(const test_crypto_ctx_t *ctx, const uint8_t nonce[MT_KEY_NONCE_LEN],
         const uint8_t *ciphertext, size_t ciphertext_len,
         uint8_t tag[MT_KEY_TAG_LEN])
{
    size_t i;
    uint8_t acc = ctx->key;

    for (i = 0; i < MT_KEY_NONCE_LEN; i++) {
        acc = (uint8_t) (acc + nonce[i] + (uint8_t) i);
    }
    for (i = 0; i < ciphertext_len; i++) {
        acc = (uint8_t) (acc + ciphertext[i] + (uint8_t) i);
    }
    for (i = 0; i < MT_KEY_TAG_LEN; i++) {
        tag[i] = (uint8_t) (acc ^ (uint8_t) (0xa5 + i));
    }
}

static int
test_seal(void *vctx, const uint8_t nonce[MT_KEY_NONCE_LEN],
          const uint8_t *plain, size_t plain_len, uint8_t *ciphertext,
          uint8_t tag[MT_KEY_TAG_LEN])
{
    test_crypto_ctx_t *ctx = (test_crypto_ctx_t *) vctx;
    size_t i;

    for (i = 0; i < plain_len; i++) {
        ciphertext[i] = (uint8_t) (plain[i] ^ test_mask(ctx, nonce, i));
    }
    test_tag(ctx, nonce, ciphertext, plain_len, tag);
    return MT_OK;
}

static int
test_open(void *vctx, const uint8_t nonce[MT_KEY_NONCE_LEN],
          const uint8_t *ciphertext, size_t ciphertext_len,
          const uint8_t tag[MT_KEY_TAG_LEN], uint8_t *plain)
{
    test_crypto_ctx_t *ctx = (test_crypto_ctx_t *) vctx;
    uint8_t expected[MT_KEY_TAG_LEN];
    size_t i;

    test_tag(ctx, nonce, ciphertext, ciphertext_len, expected);
    if (memcmp(expected, tag, MT_KEY_TAG_LEN) != 0) {
        return MT_ERR_INVALID;
    }
    for (i = 0; i < ciphertext_len; i++) {
        plain[i] = (uint8_t) (ciphertext[i] ^ test_mask(ctx, nonce, i));
    }
    return MT_OK;
}

static mt_key_crypto_t
test_crypto(test_crypto_ctx_t *ctx)
{
    mt_key_crypto_t crypto;

    crypto.ctx = ctx;
    crypto.seal = test_seal;
    crypto.open = test_open;
    return crypto;
}

static int
vector_seal(void *vctx, const uint8_t nonce[MT_KEY_NONCE_LEN],
            const uint8_t *plain, size_t plain_len, uint8_t *ciphertext,
            uint8_t tag[MT_KEY_TAG_LEN])
{
    vector_crypto_ctx_t *ctx = (vector_crypto_ctx_t *) vctx;

    assert(ctx->nonce_len == MT_KEY_NONCE_LEN);
    assert(memcmp(nonce, ctx->nonce, MT_KEY_NONCE_LEN) == 0);
    assert(plain_len == ctx->plain_len);
    assert(memcmp(plain, ctx->plain, plain_len) == 0);
    memcpy(ciphertext, ctx->ciphertext, ctx->ciphertext_len);
    memcpy(tag, ctx->tag, MT_KEY_TAG_LEN);
    return MT_OK;
}

static int
vector_open(void *vctx, const uint8_t nonce[MT_KEY_NONCE_LEN],
            const uint8_t *ciphertext, size_t ciphertext_len,
            const uint8_t tag[MT_KEY_TAG_LEN], uint8_t *plain)
{
    vector_crypto_ctx_t *ctx = (vector_crypto_ctx_t *) vctx;

    assert(ctx->nonce_len == MT_KEY_NONCE_LEN);
    assert(memcmp(nonce, ctx->nonce, MT_KEY_NONCE_LEN) == 0);
    assert(ciphertext_len == ctx->ciphertext_len);
    assert(memcmp(ciphertext, ctx->ciphertext, ciphertext_len) == 0);
    assert(memcmp(tag, ctx->tag, MT_KEY_TAG_LEN) == 0);
    memcpy(plain, ctx->plain, ctx->plain_len);
    return MT_OK;
}

static mt_key_crypto_t
vector_crypto(vector_crypto_ctx_t *ctx)
{
    mt_key_crypto_t crypto;

    crypto.ctx = ctx;
    crypto.seal = vector_seal;
    crypto.open = vector_open;
    return crypto;
}

static int
test_key_tcp_wrap_plain(uint8_t *dst, size_t dst_len,
                        const mt_key_crypto_t *crypto,
                        const uint8_t nonce[MT_KEY_NONCE_LEN],
                        const uint8_t *plain, size_t plain_len,
                        size_t *written)
{
    int rc;

    if (dst == NULL || crypto == NULL || nonce == NULL || plain == NULL
        || written == NULL || plain_len > UINT16_MAX)
    {
        return MT_ERR_INVALID;
    }

    if (dst_len < MT_KEY_NONCE_LEN + MT_KEY_TCP_LEN_LEN + plain_len
                  + MT_KEY_TAG_LEN)
    {
        return MT_ERR_NO_SPACE;
    }

    memcpy(dst, nonce, MT_KEY_NONCE_LEN);
    dst[MT_KEY_NONCE_LEN] = (uint8_t) (plain_len >> 8);
    dst[MT_KEY_NONCE_LEN + 1] = (uint8_t) plain_len;
    rc = crypto->seal(crypto->ctx, nonce, plain, plain_len,
                      &dst[MT_KEY_NONCE_LEN + MT_KEY_TCP_LEN_LEN],
                      &dst[MT_KEY_NONCE_LEN + MT_KEY_TCP_LEN_LEN
                           + plain_len]);
    if (rc != MT_OK) {
        return rc;
    }

    *written = MT_KEY_NONCE_LEN + MT_KEY_TCP_LEN_LEN + plain_len
               + MT_KEY_TAG_LEN;
    return MT_OK;
}

static void
test_tcp_bootstrap_roundtrip(void)
{
    uint8_t buf[128];
    uint8_t addr[4] = { 1, 2, 3, 4 };
    const uint8_t payload[] = "hello";
    mt_tcp_bootstrap_t decoded;
    size_t n;
    int rc;

    rc = mt_encode_tcp_bootstrap(buf, sizeof(buf), MT_CMD_CONNECT,
                                 MT_PROTECT_BOOTSTRAP, MT_ADDR_IPV4, addr,
                                 sizeof(addr), 443, payload,
                                 sizeof(payload) - 1, &n);
    assert(rc == MT_OK);
    assert(n == 6 + sizeof(addr) + sizeof(payload) - 1);

    memset(&decoded, 0, sizeof(decoded));
    rc = mt_decode_tcp_bootstrap(buf, n, &decoded, &n);
    assert(rc == MT_OK);
    assert(n == 6 + sizeof(addr));
    assert(decoded.cmd == MT_CMD_CONNECT);
    assert(decoded.flow_protection == MT_PROTECT_BOOTSTRAP);
    assert(decoded.addr.type == MT_ADDR_IPV4);
    assert(decoded.addr.port == 443);
    assert(decoded.addr.len == 4);
    assert(memcmp(decoded.addr.data, addr, sizeof(addr)) == 0);
    assert(decoded.payload_len == sizeof(payload) - 1);
    assert(memcmp(decoded.payload, payload, decoded.payload_len) == 0);
}

static void
test_tcp_bootstrap_associate_roundtrip(void)
{
    uint8_t buf[128];
    uint8_t addr[4] = { 8, 8, 8, 8 };
    mt_tcp_bootstrap_t decoded;
    size_t n;
    int rc;

    rc = mt_encode_tcp_bootstrap(buf, sizeof(buf), MT_CMD_ASSOCIATE,
                                 MT_PROTECT_BOOTSTRAP, MT_ADDR_IPV4, addr,
                                 sizeof(addr), 53, NULL, 0, &n);
    assert(rc == MT_OK);

    rc = mt_decode_tcp_bootstrap(buf, n, &decoded, &n);
    assert(rc == MT_OK);
    assert(decoded.cmd == MT_CMD_ASSOCIATE);
    assert(decoded.flow_protection == MT_PROTECT_BOOTSTRAP);
    assert(decoded.addr.type == MT_ADDR_IPV4);
    assert(decoded.addr.port == 53);
    assert(decoded.payload_len == 0);
}

static void
test_tcp_domain_bootstrap_protect(void)
{
    uint8_t buf[128];
    const uint8_t domain[] = "example.com";
    mt_tcp_bootstrap_t decoded;
    size_t n;
    int rc;

    rc = mt_encode_tcp_bootstrap(buf, sizeof(buf), MT_CMD_CONNECT,
                                 MT_PROTECT_BOOTSTRAP, MT_ADDR_DOMAIN,
                                 domain, sizeof(domain) - 1, 8443, NULL, 0,
                                 &n);
    assert(rc == MT_OK);

    rc = mt_decode_tcp_bootstrap(buf, n, &decoded, &n);
    assert(rc == MT_OK);
    assert(decoded.cmd == MT_CMD_CONNECT);
    assert(decoded.flow_protection == MT_PROTECT_BOOTSTRAP);
    assert(decoded.addr.type == MT_ADDR_DOMAIN);
    assert(decoded.addr.port == 8443);
    assert(decoded.addr.len == sizeof(domain) - 1);
    assert(memcmp(decoded.addr.data, domain, decoded.addr.len) == 0);
    assert(decoded.payload_len == 0);
}

static void
test_udp_init_roundtrip(void)
{
    uint8_t buf[128];
    uint8_t flow_id[MT_FLOW_ID_LEN] = { 0x7f, 1, 2, 3, 4, 5, 6, 7 };
    uint8_t addr[4] = { 8, 8, 8, 8 };
    const uint8_t payload[] = "dns";
    mt_udp_init_t decoded;
    size_t n;
    int rc;

    mt_flow_id_prepare(flow_id);
    rc = mt_encode_udp_init(buf, sizeof(buf), MT_PROTECT_BOOTSTRAP, flow_id,
                            MT_ADDR_IPV4, addr, sizeof(addr), 53, payload,
                            sizeof(payload) - 1, &n);
    assert(rc == MT_OK);
    assert((buf[0] & 0xc0) == MT_PACKET_INIT);

    rc = mt_decode_udp_init(buf, n, &decoded, &n);
    assert(rc == MT_OK);
    assert(decoded.flow_protection == MT_PROTECT_BOOTSTRAP);
    assert(memcmp(decoded.flow_id, flow_id, MT_FLOW_ID_LEN) == 0);
    assert(decoded.addr.type == MT_ADDR_IPV4);
    assert(decoded.addr.port == 53);
    assert(decoded.payload_len == sizeof(payload) - 1);
    assert(memcmp(decoded.payload, payload, decoded.payload_len) == 0);
}

static void
test_no_key_rejects_protected_profiles(void)
{
    uint8_t buf[128];
    uint8_t flow_id[MT_FLOW_ID_LEN] = { 0x01, 1, 2, 3, 4, 5, 6, 7 };
    uint8_t addr[4] = { 1, 2, 3, 4 };
    const uint8_t tcp_wire[] = {
        MT_CMD_CONNECT,
        MT_PROTECT_FULL,
        MT_ADDR_IPV4, 0x04, 1, 2, 3, 4, 0x00, 0x50
    };
    uint8_t udp_wire[] = {
        (uint8_t) (MT_PACKET_INIT | MT_PROTECT_HANDSHAKE),
        0x01, 1, 2, 3, 4, 5, 6, 7,
        MT_ADDR_IPV4, 0x04, 1, 2, 3, 4, 0x00, 0x35
    };
    mt_tcp_bootstrap_t tcp;
    mt_udp_init_t udp;
    size_t n;
    int rc;

    mt_flow_id_prepare(flow_id);

    rc = mt_encode_tcp_bootstrap(buf, sizeof(buf), MT_CMD_CONNECT,
                                 MT_PROTECT_HANDSHAKE, MT_ADDR_IPV4, addr,
                                 sizeof(addr), 80, NULL, 0, &n);
    assert(rc == MT_ERR_INVALID);

    rc = mt_encode_tcp_bootstrap(buf, sizeof(buf), MT_CMD_CONNECT,
                                 MT_PROTECT_FULL, MT_ADDR_IPV4, addr,
                                 sizeof(addr), 80, NULL, 0, &n);
    assert(rc == MT_ERR_INVALID);

    rc = mt_decode_tcp_bootstrap(tcp_wire, sizeof(tcp_wire), &tcp, &n);
    assert(rc == MT_ERR_INVALID);

    rc = mt_encode_udp_init(buf, sizeof(buf), MT_PROTECT_HANDSHAKE, flow_id,
                            MT_ADDR_IPV4, addr, sizeof(addr), 53, NULL, 0,
                            &n);
    assert(rc == MT_ERR_INVALID);

    rc = mt_encode_udp_init(buf, sizeof(buf), MT_PROTECT_FULL, flow_id,
                            MT_ADDR_IPV4, addr, sizeof(addr), 53, NULL, 0,
                            &n);
    assert(rc == MT_ERR_INVALID);

    rc = mt_decode_udp_init(udp_wire, sizeof(udp_wire), &udp, &n);
    assert(rc == MT_ERR_INVALID);
}

static void
test_udp_data_roundtrip(void)
{
    uint8_t buf[128];
    uint8_t flow_id[MT_FLOW_ID_LEN] = { 0xff, 1, 2, 3, 4, 5, 6, 7 };
    const uint8_t payload[] = "packet";
    mt_udp_data_t decoded;
    size_t n;
    int rc;

    mt_flow_id_prepare(flow_id);
    rc = mt_encode_udp_data(buf, sizeof(buf), flow_id, payload,
                            sizeof(payload) - 1, &n);
    assert(rc == MT_OK);
    assert((buf[0] & 0xc0) == MT_PACKET_DATA);

    rc = mt_decode_udp_data(buf, n, &decoded, &n);
    assert(rc == MT_OK);
    assert(memcmp(decoded.flow_id, flow_id, MT_FLOW_ID_LEN) == 0);
    assert(decoded.payload_len == sizeof(payload) - 1);
    assert(memcmp(decoded.payload, payload, decoded.payload_len) == 0);
}

static void
test_udp_stream_frame_roundtrip(void)
{
    uint8_t buf[128];
    uint8_t addr[16] = {
        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 1
    };
    const uint8_t payload[] = "udp-over-stream";
    mt_udp_stream_frame_t decoded;
    size_t n;
    int rc;

    rc = mt_encode_udp_stream_frame(buf, sizeof(buf), MT_ADDR_IPV6, addr,
                                    sizeof(addr), 5353, payload,
                                    sizeof(payload) - 1, &n);
    assert(rc == MT_OK);

    rc = mt_decode_udp_stream_frame(buf, n, &decoded, &n);
    assert(rc == MT_OK);
    assert(n == mt_udp_stream_frame_size(MT_ADDR_IPV6, sizeof(addr),
                                         sizeof(payload) - 1));
    assert(decoded.addr.type == MT_ADDR_IPV6);
    assert(decoded.addr.port == 5353);
    assert(decoded.payload_len == sizeof(payload) - 1);
    assert(memcmp(decoded.payload, payload, decoded.payload_len) == 0);
}

static void
test_key_tcp_bootstrap_roundtrip(void)
{
    test_crypto_ctx_t crypto_ctx = { 0x33 };
    mt_key_crypto_t crypto = test_crypto(&crypto_ctx);
    const uint8_t nonce[MT_KEY_NONCE_LEN] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
        0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c
    };
    const uint8_t domain[] = "example.com";
    const uint8_t payload[] = "clienthello";
    uint8_t wire[256];
    uint8_t plain[256];
    mt_key_tcp_bootstrap_t decoded;
    size_t n;
    int rc;

    rc = mt_encode_key_tcp_bootstrap(wire, sizeof(wire), &crypto, nonce, 12345,
                                     MT_CMD_CONNECT,
                                     MT_PROTECT_HANDSHAKE,
                                     MT_ADDR_DOMAIN, domain,
                                     sizeof(domain) - 1, 443, payload,
                                     sizeof(payload) - 1, &n);
    assert(rc == MT_OK);
    assert(n == mt_key_tcp_bootstrap_size(MT_ADDR_DOMAIN,
                                          sizeof(domain) - 1,
                                          sizeof(payload) - 1));
    assert(memcmp(wire, nonce, MT_KEY_NONCE_LEN) == 0);

    rc = mt_decode_key_tcp_bootstrap(wire, n, &crypto, plain, sizeof(plain),
                                     &decoded, &n);
    assert(rc == MT_OK);
    assert(decoded.epoch == 12345);
    assert(memcmp(decoded.nonce, nonce, MT_KEY_NONCE_LEN) == 0);
    assert(decoded.cmd == MT_CMD_CONNECT);
    assert(decoded.flow_protection == MT_PROTECT_HANDSHAKE);
    assert(decoded.addr.type == MT_ADDR_DOMAIN);
    assert(decoded.addr.port == 443);
    assert(decoded.addr.len == sizeof(domain) - 1);
    assert(memcmp(decoded.addr.data, domain, decoded.addr.len) == 0);
    assert(decoded.payload_len == sizeof(payload) - 1);
    assert(memcmp(decoded.payload, payload, decoded.payload_len) == 0);
}

static void
test_key_tcp_bootstrap_associate_cmd(void)
{
    test_crypto_ctx_t crypto_ctx = { 0x34 };
    mt_key_crypto_t crypto = test_crypto(&crypto_ctx);
    const uint8_t nonce[MT_KEY_NONCE_LEN] = {
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16,
        0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c
    };
    uint8_t addr[4] = { 1, 1, 1, 1 };
    uint8_t wire[128];
    uint8_t plain[128];
    mt_key_tcp_bootstrap_t decoded;
    size_t n;
    int rc;

    rc = mt_encode_key_tcp_bootstrap(wire, sizeof(wire), &crypto, nonce, 678,
                                     MT_CMD_ASSOCIATE,
                                     MT_PROTECT_FULL, MT_ADDR_IPV4, addr,
                                     sizeof(addr), 53, NULL, 0, &n);
    assert(rc == MT_OK);

    rc = mt_decode_key_tcp_bootstrap(wire, n, &crypto, plain, sizeof(plain),
                                     &decoded, &n);
    assert(rc == MT_OK);
    assert(decoded.epoch == 678);
    assert(decoded.cmd == MT_CMD_ASSOCIATE);
    assert(decoded.flow_protection == MT_PROTECT_FULL);
    assert(decoded.addr.type == MT_ADDR_IPV4);
    assert(decoded.addr.port == 53);
    assert(decoded.payload_len == 0);
}

static void
test_key_tcp_bootstrap_consumes_only_wrapper(void)
{
    test_crypto_ctx_t crypto_ctx = { 0x35 };
    mt_key_crypto_t crypto = test_crypto(&crypto_ctx);
    const uint8_t nonce[MT_KEY_NONCE_LEN] = {
        0x21, 0x22, 0x23, 0x24, 0x25, 0x26,
        0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c
    };
    uint8_t addr[4] = { 203, 0, 113, 9 };
    const uint8_t payload[] = "hello";
    const uint8_t raw[] = "raw-relay-bytes";
    uint8_t wire[256];
    uint8_t plain[256];
    mt_key_tcp_bootstrap_t decoded;
    size_t n, encoded, consumed;
    int rc;

    rc = mt_encode_key_tcp_bootstrap(wire, sizeof(wire), &crypto, nonce, 456,
                                     MT_CMD_CONNECT,
                                     MT_PROTECT_BOOTSTRAP, MT_ADDR_IPV4,
                                     addr, sizeof(addr), 443, payload,
                                     sizeof(payload) - 1, &encoded);
    assert(rc == MT_OK);
    assert(encoded + sizeof(raw) - 1 <= sizeof(wire));
    memcpy(wire + encoded, raw, sizeof(raw) - 1);
    n = encoded + sizeof(raw) - 1;

    rc = mt_decode_key_tcp_bootstrap(wire, n, &crypto, plain, sizeof(plain),
                                     &decoded, &consumed);
    assert(rc == MT_OK);
    assert(consumed == encoded);
    assert(decoded.epoch == 456);
    assert(decoded.cmd == MT_CMD_CONNECT);
    assert(decoded.payload_len == sizeof(payload) - 1);
    assert(memcmp(decoded.payload, payload, decoded.payload_len) == 0);
    assert(memcmp(wire + consumed, raw, sizeof(raw) - 1) == 0);
}

static void
test_key_tcp_bootstrap_truncated_wrapper_returns_again(void)
{
    test_crypto_ctx_t crypto_ctx = { 0x36 };
    mt_key_crypto_t crypto = test_crypto(&crypto_ctx);
    const uint8_t nonce[MT_KEY_NONCE_LEN] = {
        0x31, 0x32, 0x33, 0x34, 0x35, 0x36,
        0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c
    };
    uint8_t addr[4] = { 192, 0, 2, 10 };
    uint8_t wire[128];
    uint8_t plain[128];
    mt_key_tcp_bootstrap_t decoded;
    size_t n, consumed;
    int rc;

    rc = mt_encode_key_tcp_bootstrap(wire, sizeof(wire), &crypto, nonce, 789,
                                     MT_CMD_CONNECT,
                                     MT_PROTECT_BOOTSTRAP, MT_ADDR_IPV4,
                                     addr, sizeof(addr), 80, NULL, 0, &n);
    assert(rc == MT_OK);
    assert(n > MT_KEY_NONCE_LEN + MT_KEY_TCP_LEN_LEN + MT_KEY_TAG_LEN);

    rc = mt_decode_key_tcp_bootstrap(wire, n - 1, &crypto, plain,
                                     sizeof(plain), &decoded, &consumed);
    assert(rc == MT_ERR_AGAIN);
}

static void
test_key_udp_init_roundtrip(void)
{
    test_crypto_ctx_t crypto_ctx = { 0x44 };
    mt_key_crypto_t crypto = test_crypto(&crypto_ctx);
    const uint8_t nonce[MT_KEY_NONCE_LEN] = {
        0x01, 0x12, 0x23, 0x34, 0x45, 0x56,
        0x67, 0x78, 0x89, 0x9a, 0xab, 0xbc
    };
    uint8_t flow_id[MT_FLOW_ID_LEN] = { 0xff, 1, 2, 3, 4, 5, 6, 7 };
    uint8_t addr[4] = { 8, 8, 8, 8 };
    const uint8_t payload[] = "dns";
    uint8_t wire[256];
    uint8_t plain[256];
    mt_key_udp_init_t decoded;
    size_t n;
    int rc;

    mt_flow_id_prepare(flow_id);
    rc = mt_encode_key_udp_init(wire, sizeof(wire), &crypto, nonce, 77,
                                MT_PROTECT_FULL, flow_id,
                                MT_ADDR_IPV4, addr, sizeof(addr), 53,
                                payload, sizeof(payload) - 1, &n);
    assert(rc == MT_OK);
    assert((wire[0] & 0xc0) == MT_PACKET_INIT);

    rc = mt_decode_key_udp_init(wire, n, &crypto, plain, sizeof(plain),
                                &decoded, &n);
    assert(rc == MT_OK);
    assert(decoded.epoch == 77);
    assert((decoded.nonce[0] & 0xc0) == MT_PACKET_INIT);
    assert(decoded.flow_protection == MT_PROTECT_FULL);
    assert(memcmp(decoded.flow_id, flow_id, MT_FLOW_ID_LEN) == 0);
    assert(decoded.addr.type == MT_ADDR_IPV4);
    assert(decoded.addr.port == 53);
    assert(decoded.payload_len == sizeof(payload) - 1);
    assert(memcmp(decoded.payload, payload, decoded.payload_len) == 0);
}

static void
test_key_udp_init_rejects_payload_limit(void)
{
    test_crypto_ctx_t crypto_ctx = { 0x45 };
    mt_key_crypto_t crypto = test_crypto(&crypto_ctx);
    const uint8_t nonce[MT_KEY_NONCE_LEN] = {
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16,
        0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c
    };
    uint8_t flow_id[MT_FLOW_ID_LEN] = { 0x01, 1, 2, 3, 4, 5, 6, 7 };
    uint8_t addr[4] = { 8, 8, 4, 4 };
    uint8_t payload[MT_BOOTSTRAP_PAYLOAD_MAX + 1];
    uint8_t wire[64];
    size_t n;
    int rc;

    memset(payload, 0xa5, sizeof(payload));
    mt_flow_id_prepare(flow_id);

    rc = mt_encode_key_udp_init(wire, sizeof(wire), &crypto, nonce, 88,
                                MT_PROTECT_HANDSHAKE, flow_id, MT_ADDR_IPV4,
                                addr, sizeof(addr), 443, payload,
                                sizeof(payload), &n);
    assert(rc == MT_ERR_INVALID);
}

static void
test_key_udp_nonce_helpers(void)
{
    uint8_t nonce[MT_KEY_NONCE_LEN] = {
        0x01, 0x12, 0x23, 0x34, 0x45, 0x56,
        0x67, 0x78, 0x89, 0x9a, 0xab, 0xbc
    };

    assert(!mt_key_udp_nonce_valid(NULL));
    assert(!mt_key_udp_nonce_valid(nonce));

    mt_key_udp_nonce_prepare(nonce);
    assert(mt_key_udp_nonce_valid(nonce));
    assert((nonce[0] & 0xc0) == MT_PACKET_INIT);
}

static void
test_key_reject_truncated_and_small_plain_buffer(void)
{
    test_crypto_ctx_t crypto_ctx = { 0x61 };
    mt_key_crypto_t crypto = test_crypto(&crypto_ctx);
    const uint8_t nonce[MT_KEY_NONCE_LEN] = {
        0x31, 0x32, 0x33, 0x34, 0x35, 0x36,
        0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c
    };
    uint8_t addr[4] = { 9, 9, 9, 9 };
    uint8_t wire[128];
    uint8_t plain[1];
    mt_key_tcp_bootstrap_t decoded;
    size_t n;
    int rc;

    rc = mt_encode_key_tcp_bootstrap(wire, sizeof(wire), &crypto, nonce, 99,
                                     MT_CMD_CONNECT,
                                     MT_PROTECT_BOOTSTRAP, MT_ADDR_IPV4,
                                     addr, sizeof(addr), 80, NULL, 0, &n);
    assert(rc == MT_OK);

    rc = mt_decode_key_tcp_bootstrap(wire, MT_KEY_NONCE_LEN + MT_KEY_TAG_LEN - 1,
                                     &crypto, plain, sizeof(plain), &decoded,
                                     &n);
    assert(rc == MT_ERR_AGAIN);

    rc = mt_decode_key_tcp_bootstrap(wire, n, &crypto, plain, sizeof(plain),
                                     &decoded, &n);
    assert(rc == MT_ERR_NO_SPACE);
}

static void
test_key_reject_invalid_plain_flow_protection(void)
{
    test_crypto_ctx_t crypto_ctx = { 0x62 };
    mt_key_crypto_t crypto = test_crypto(&crypto_ctx);
    const uint8_t nonce[MT_KEY_NONCE_LEN] = {
        0x41, 0x42, 0x43, 0x44, 0x45, 0x46,
        0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c
    };
    const uint8_t bad_plain[] = {
        0x00, 0x00, 0x00, 0x01,
        MT_CMD_CONNECT,
        0x3f,
        MT_ADDR_IPV4, 0x04, 1, 2, 3, 4, 0x00, 0x50
    };
    uint8_t wire[128];
    uint8_t plain[128];
    mt_key_tcp_bootstrap_t decoded;
    size_t n;
    int rc;

    rc = test_key_tcp_wrap_plain(wire, sizeof(wire), &crypto, nonce,
                                 bad_plain, sizeof(bad_plain), &n);
    assert(rc == MT_OK);

    rc = mt_decode_key_tcp_bootstrap(wire, n, &crypto, plain, sizeof(plain),
                                     &decoded, &n);
    assert(rc == MT_ERR_INVALID);
}

static void
test_key_reject_invalid_plain_cmd(void)
{
    test_crypto_ctx_t crypto_ctx = { 0x64 };
    mt_key_crypto_t crypto = test_crypto(&crypto_ctx);
    const uint8_t nonce[MT_KEY_NONCE_LEN] = {
        0x61, 0x62, 0x63, 0x64, 0x65, 0x66,
        0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c
    };
    const uint8_t bad_plain[] = {
        0x00, 0x00, 0x00, 0x01,
        0x7f,
        MT_PROTECT_BOOTSTRAP,
        MT_ADDR_IPV4, 0x04, 1, 2, 3, 4, 0x00, 0x50
    };
    uint8_t wire[128];
    uint8_t plain[128];
    mt_key_tcp_bootstrap_t decoded;
    size_t n;
    int rc;

    rc = test_key_tcp_wrap_plain(wire, sizeof(wire), &crypto, nonce,
                                 bad_plain, sizeof(bad_plain), &n);
    assert(rc == MT_OK);

    rc = mt_decode_key_tcp_bootstrap(wire, n, &crypto, plain, sizeof(plain),
                                     &decoded, &n);
    assert(rc == MT_ERR_INVALID);
}

static void
test_key_reject_bad_udp_nonce_class(void)
{
    test_crypto_ctx_t crypto_ctx = { 0x63 };
    mt_key_crypto_t crypto = test_crypto(&crypto_ctx);
    const uint8_t nonce[MT_KEY_NONCE_LEN] = {
        0x51, 0x52, 0x53, 0x54, 0x55, 0x56,
        0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c
    };
    uint8_t flow_id[MT_FLOW_ID_LEN] = { 0x01, 1, 2, 3, 4, 5, 6, 7 };
    uint8_t addr[4] = { 4, 3, 2, 1 };
    uint8_t wire[128];
    uint8_t plain[128];
    mt_key_udp_init_t decoded;
    size_t n;
    int rc;

    mt_flow_id_prepare(flow_id);
    rc = mt_encode_key_udp_init(wire, sizeof(wire), &crypto, nonce, 100,
                                MT_PROTECT_BOOTSTRAP, flow_id, MT_ADDR_IPV4,
                                addr, sizeof(addr), 53, NULL, 0, &n);
    assert(rc == MT_OK);

    wire[0] &= 0x3f;
    rc = mt_decode_key_udp_init(wire, n, &crypto, plain, sizeof(plain),
                                &decoded, &n);
    assert(rc == MT_ERR_INVALID);
}

static void
test_key_reject_wrong_crypto_and_tamper(void)
{
    test_crypto_ctx_t crypto_ctx = { 0x55 };
    test_crypto_ctx_t wrong_crypto_ctx = { 0x56 };
    mt_key_crypto_t crypto = test_crypto(&crypto_ctx);
    mt_key_crypto_t wrong_crypto = test_crypto(&wrong_crypto_ctx);
    const uint8_t nonce[MT_KEY_NONCE_LEN] = {
        0x21, 0x22, 0x23, 0x24, 0x25, 0x26,
        0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c
    };
    uint8_t addr[4] = { 1, 1, 1, 1 };
    uint8_t wire[128];
    uint8_t plain[128];
    mt_key_tcp_bootstrap_t decoded;
    size_t n;
    int rc;

    rc = mt_encode_key_tcp_bootstrap(wire, sizeof(wire), &crypto, nonce, 1,
                                     MT_CMD_CONNECT,
                                     MT_PROTECT_BOOTSTRAP, MT_ADDR_IPV4,
                                     addr, sizeof(addr), 80, NULL, 0, &n);
    assert(rc == MT_OK);

    rc = mt_decode_key_tcp_bootstrap(wire, n, &wrong_crypto, plain,
                                     sizeof(plain), &decoded, &n);
    assert(rc == MT_ERR_INVALID);

    wire[n - 1] ^= 0x01;
    rc = mt_decode_key_tcp_bootstrap(wire, n, &crypto, plain, sizeof(plain),
                                     &decoded, &n);
    assert(rc == MT_ERR_INVALID);
}

static void
test_public_test_vectors(void)
{
    const uint8_t addr4[4] = { 1, 2, 3, 4 };
    const uint8_t tcp_payload[5] = { 'h', 'e', 'l', 'l', 'o' };
    const uint8_t udp_payload[3] = { 'd', 'n', 's' };
    const uint8_t data_payload[4] = { 'q', 'u', 'i', 'c' };
    const uint8_t domain[11] = { 'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm' };
    uint8_t flow_id[MT_FLOW_ID_LEN];
    uint8_t nonce[MT_KEY_NONCE_LEN];
    uint8_t plain[128];
    uint8_t ciphertext[128];
    uint8_t tag[MT_KEY_TAG_LEN];
    uint8_t wire[256];
    mt_tcp_bootstrap_t tcp;
    mt_udp_init_t udp_init;
    mt_udp_data_t udp_data;
    mt_key_tcp_bootstrap_t key_tcp;
    mt_key_udp_init_t key_udp;
    vector_crypto_ctx_t vctx;
    mt_key_crypto_t crypto;
    size_t n, consumed;
    int rc;

    static const char v1_wire[] =
        "010001040102030401bb68656c6c6f";
    static const char v2_flow_input[] =
        "c122334455667788";
    static const char v2_flow_prepared[] =
        "0122334455667788";
    static const char v2_wire[] =
        "8001223344556677880104010203040035646e73";
    static const char v3_wire[] =
        "012233445566778871756963";
    static const char v4_nonce[] =
        "000102030405060708090a0b";
    static const char v4_plain[] =
        "010203040101030b6578616d706c652e636f6d01bb68656c6c6f";
    static const char v4_session_key[] =
        "78a40269279f651f6689db6a344a0e20";
    static const char v4_ciphertext[] =
        "0212290ac4041f48dd18cd7cdbc9393a8c1ee2b41adc913ae17f";
    static const char v4_tag[] =
        "8226741b34ba8b3b871057ea594ea707";
    static const char v4_wire[] =
        "000102030405060708090a0b001a0212290ac4041f48dd18cd7cdbc9393a8c1ee2b41adc913ae17f8226741b34ba8b3b871057ea594ea707";
    static const char v5_nonce_input[] =
        "01112233445566778899aabb";
    static const char v5_nonce_normalized[] =
        "81112233445566778899aabb";
    static const char v5_plain[] =
        "010203040201223344556677880104010203040035646e73";
    static const char v5_session_key[] =
        "840dcddd428802a3b7618994387f6a34";
    static const char v5_ciphertext[] =
        "6c89b5fcb16f159698024928236e23ee33c55a72befa8ddf";
    static const char v5_tag[] =
        "d7d2aee47fefc1300ca3d3f046b784d8";
    static const char v5_wire[] =
        "81112233445566778899aabb6c89b5fcb16f159698024928236e23ee33c55a72befa8ddfd7d2aee47fefc1300ca3d3f046b784d8";

    assert_readme_contains(v1_wire);
    assert_readme_contains(v2_wire);
    assert_readme_contains(v3_wire);
    assert_readme_contains(v4_session_key);
    assert_readme_contains(v4_wire);
    assert_readme_contains(v5_session_key);
    assert_readme_contains(v5_wire);

    rc = mt_encode_tcp_bootstrap(wire, sizeof(wire), MT_CMD_CONNECT,
                                 MT_PROTECT_BOOTSTRAP, MT_ADDR_IPV4,
                                 addr4, sizeof(addr4), 443,
                                 tcp_payload, sizeof(tcp_payload), &n);
    assert(rc == MT_OK);
    assert_hex_eq(wire, n, v1_wire);
    rc = mt_decode_tcp_bootstrap(wire, n, &tcp, &consumed);
    assert(rc == MT_OK);
    assert(consumed == 10);
    assert(tcp.cmd == MT_CMD_CONNECT);
    assert(tcp.flow_protection == MT_PROTECT_BOOTSTRAP);
    assert(tcp.addr.type == MT_ADDR_IPV4);
    assert(tcp.addr.port == 443);
    assert(memcmp(tcp.addr.data, addr4, sizeof(addr4)) == 0);
    assert(tcp.payload_len == sizeof(tcp_payload));
    assert(memcmp(tcp.payload, tcp_payload, sizeof(tcp_payload)) == 0);

    hex_to_bytes(v2_flow_input, flow_id, sizeof(flow_id));
    mt_flow_id_prepare(flow_id);
    assert_hex_eq(flow_id, sizeof(flow_id), v2_flow_prepared);
    rc = mt_encode_udp_init(wire, sizeof(wire), MT_PROTECT_BOOTSTRAP,
                            flow_id, MT_ADDR_IPV4, addr4, sizeof(addr4), 53,
                            udp_payload, sizeof(udp_payload), &n);
    assert(rc == MT_OK);
    assert_hex_eq(wire, n, v2_wire);
    rc = mt_decode_udp_init(wire, n, &udp_init, &consumed);
    assert(rc == MT_OK);
    assert(consumed == 17);
    assert(udp_init.flow_protection == MT_PROTECT_BOOTSTRAP);
    assert(memcmp(udp_init.flow_id, flow_id, sizeof(flow_id)) == 0);
    assert(udp_init.addr.type == MT_ADDR_IPV4);
    assert(udp_init.addr.port == 53);
    assert(memcmp(udp_init.addr.data, addr4, sizeof(addr4)) == 0);
    assert(udp_init.payload_len == sizeof(udp_payload));
    assert(memcmp(udp_init.payload, udp_payload, sizeof(udp_payload)) == 0);

    rc = mt_encode_udp_data(wire, sizeof(wire), flow_id,
                            data_payload, sizeof(data_payload), &n);
    assert(rc == MT_OK);
    assert_hex_eq(wire, n, v3_wire);
    rc = mt_decode_udp_data(wire, n, &udp_data, &consumed);
    assert(rc == MT_OK);
    assert(consumed == n);
    assert(memcmp(udp_data.flow_id, flow_id, sizeof(flow_id)) == 0);
    assert(udp_data.payload_len == sizeof(data_payload));
    assert(memcmp(udp_data.payload, data_payload, sizeof(data_payload)) == 0);

    vctx.nonce_len = hex_to_bytes(v4_nonce, nonce, sizeof(nonce));
    vctx.nonce = nonce;
    vctx.plain_len = hex_to_bytes(v4_plain, plain, sizeof(plain));
    vctx.plain = plain;
    vctx.ciphertext_len = hex_to_bytes(v4_ciphertext, ciphertext,
                                       sizeof(ciphertext));
    vctx.ciphertext = ciphertext;
    hex_to_bytes(v4_tag, tag, sizeof(tag));
    vctx.tag = tag;
    crypto = vector_crypto(&vctx);
    rc = mt_encode_key_tcp_bootstrap(wire, sizeof(wire), &crypto, nonce,
                                     0x01020304, MT_CMD_CONNECT,
                                     MT_PROTECT_HANDSHAKE, MT_ADDR_DOMAIN,
                                     domain, sizeof(domain), 443,
                                     tcp_payload, sizeof(tcp_payload), &n);
    assert(rc == MT_OK);
    assert_hex_eq(wire, n, v4_wire);
    rc = mt_decode_key_tcp_bootstrap(wire, n, &crypto, plain, sizeof(plain),
                                     &key_tcp, &consumed);
    assert(rc == MT_OK);
    assert(consumed == n);
    assert(key_tcp.epoch == 0x01020304);
    assert(key_tcp.cmd == MT_CMD_CONNECT);
    assert(key_tcp.flow_protection == MT_PROTECT_HANDSHAKE);
    assert(key_tcp.addr.type == MT_ADDR_DOMAIN);
    assert(key_tcp.addr.port == 443);
    assert(memcmp(key_tcp.addr.data, domain, sizeof(domain)) == 0);
    assert(key_tcp.payload_len == sizeof(tcp_payload));
    assert(memcmp(key_tcp.payload, tcp_payload, sizeof(tcp_payload)) == 0);

    hex_to_bytes(v5_nonce_input, nonce, sizeof(nonce));
    mt_key_udp_nonce_prepare(nonce);
    assert_hex_eq(nonce, sizeof(nonce), v5_nonce_normalized);
    vctx.nonce = nonce;
    vctx.nonce_len = MT_KEY_NONCE_LEN;
    vctx.plain_len = hex_to_bytes(v5_plain, plain, sizeof(plain));
    vctx.plain = plain;
    vctx.ciphertext_len = hex_to_bytes(v5_ciphertext, ciphertext,
                                       sizeof(ciphertext));
    vctx.ciphertext = ciphertext;
    hex_to_bytes(v5_tag, tag, sizeof(tag));
    vctx.tag = tag;
    crypto = vector_crypto(&vctx);
    rc = mt_encode_key_udp_init(wire, sizeof(wire), &crypto, nonce,
                                0x01020304, MT_PROTECT_FULL, flow_id,
                                MT_ADDR_IPV4, addr4, sizeof(addr4), 53,
                                udp_payload, sizeof(udp_payload), &n);
    assert(rc == MT_OK);
    assert_hex_eq(wire, n, v5_wire);
    rc = mt_decode_key_udp_init(wire, n, &crypto, plain, sizeof(plain),
                                &key_udp, &consumed);
    assert(rc == MT_OK);
    assert(consumed == n);
    assert(key_udp.epoch == 0x01020304);
    assert(key_udp.flow_protection == MT_PROTECT_FULL);
    assert(memcmp(key_udp.flow_id, flow_id, sizeof(flow_id)) == 0);
    assert(key_udp.addr.type == MT_ADDR_IPV4);
    assert(key_udp.addr.port == 53);
    assert(memcmp(key_udp.addr.data, addr4, sizeof(addr4)) == 0);
    assert(key_udp.payload_len == sizeof(udp_payload));
    assert(memcmp(key_udp.payload, udp_payload, sizeof(udp_payload)) == 0);
}

static void
test_protocol_limit_constants(void)
{
    uint8_t addr[4] = { 127, 0, 0, 1 };

    assert(MT_BOOTSTRAP_PAYLOAD_MAX >= 1200);
    assert(MT_KEY_PLAIN_MAX >= MT_BOOTSTRAP_PAYLOAD_MAX);
    assert(MT_UDP_DATAGRAM_SAFE_MAX >= 1200);
    assert(mt_tcp_bootstrap_size(MT_ADDR_IPV4, sizeof(addr),
                                 MT_BOOTSTRAP_PAYLOAD_MAX + 1)
           == 0);
    assert(mt_udp_init_size(MT_ADDR_IPV4, sizeof(addr),
                            MT_BOOTSTRAP_PAYLOAD_MAX + 1)
           == 0);
    assert(mt_key_wire_size(MT_KEY_PLAIN_MAX + 1) == 0);
}

static void
test_packet_class_helpers(void)
{
    uint8_t data[1] = { MT_PACKET_DATA };
    uint8_t init[1] = { MT_PACKET_INIT };
    uint8_t reserved[1] = { 0x40 };

    assert(mt_udp_packet_class(data, sizeof(data)) == MT_PACKET_DATA);
    assert(mt_udp_packet_class(init, sizeof(init)) == MT_PACKET_INIT);
    assert(mt_udp_packet_class(reserved, sizeof(reserved)) == MT_PACKET_RESERVED1);
}

static void
test_reject_reserved_packet_classes(void)
{
    uint8_t reserved1[MT_FLOW_ID_LEN + 8] = { MT_PACKET_RESERVED1 };
    uint8_t reserved2[MT_FLOW_ID_LEN + 8] = { MT_PACKET_RESERVED2 };
    mt_udp_init_t init;
    mt_udp_data_t data;
    size_t n;

    assert(mt_decode_udp_init(reserved1, sizeof(reserved1), &init, &n)
           == MT_ERR_INVALID);
    assert(mt_decode_udp_init(reserved2, sizeof(reserved2), &init, &n)
           == MT_ERR_INVALID);
    assert(mt_decode_udp_data(reserved1, sizeof(reserved1), &data, &n)
           == MT_ERR_INVALID);
    assert(mt_decode_udp_data(reserved2, sizeof(reserved2), &data, &n)
           == MT_ERR_INVALID);
}

static void
test_reject_invalid_inputs(void)
{
    uint8_t buf[64] = {0};
    uint8_t addr[4] = { 127, 0, 0, 1 };
    uint8_t bad_flow[MT_FLOW_ID_LEN] = { 0x80, 1, 2, 3, 4, 5, 6, 7 };
    mt_tcp_bootstrap_t tcp;
    mt_udp_init_t init;
    mt_udp_data_t data;
    mt_udp_stream_frame_t frame;
    size_t n;

    assert(mt_decode_tcp_bootstrap(buf, 2, &tcp, &n) == MT_ERR_AGAIN);
    assert(mt_encode_tcp_bootstrap(buf, sizeof(buf), 0x7f,
                                   MT_PROTECT_BOOTSTRAP, MT_ADDR_IPV4, addr,
                                   sizeof(addr), 80, NULL, 0, &n)
           == MT_ERR_INVALID);
    assert(mt_encode_tcp_bootstrap(buf, sizeof(buf), MT_CMD_CONNECT, 63,
                                   MT_ADDR_IPV4, addr, sizeof(addr), 80,
                                   NULL, 0, &n)
           == MT_ERR_INVALID);
    assert(mt_encode_tcp_bootstrap(buf, sizeof(buf), MT_CMD_CONNECT,
                                   MT_PROTECT_BOOTSTRAP, MT_ADDR_IPV4, addr,
                                   3, 80, NULL, 0, &n)
           == MT_ERR_INVALID);
    assert(mt_encode_udp_data(buf, sizeof(buf), bad_flow, NULL, 0, &n)
           == MT_ERR_INVALID);
    assert(mt_decode_udp_init(buf, sizeof(buf), &init, &n) == MT_ERR_INVALID);
    buf[0] = MT_PACKET_INIT;
    assert(mt_decode_udp_data(buf, sizeof(buf), &data, &n) == MT_ERR_INVALID);
    assert(mt_decode_udp_stream_frame(buf, 1, &frame, &n) == MT_ERR_AGAIN);
}

int
main(void)
{
    test_tcp_bootstrap_roundtrip();
    test_tcp_bootstrap_associate_roundtrip();
    test_tcp_domain_bootstrap_protect();
    test_udp_init_roundtrip();
    test_no_key_rejects_protected_profiles();
    test_udp_data_roundtrip();
    test_udp_stream_frame_roundtrip();
    test_key_tcp_bootstrap_roundtrip();
    test_key_tcp_bootstrap_associate_cmd();
    test_key_tcp_bootstrap_consumes_only_wrapper();
    test_key_tcp_bootstrap_truncated_wrapper_returns_again();
    test_key_udp_init_roundtrip();
    test_key_udp_init_rejects_payload_limit();
    test_key_udp_nonce_helpers();
    test_key_reject_truncated_and_small_plain_buffer();
    test_key_reject_invalid_plain_flow_protection();
    test_key_reject_invalid_plain_cmd();
    test_key_reject_bad_udp_nonce_class();
    test_key_reject_wrong_crypto_and_tamper();
    test_protocol_limit_constants();
    test_packet_class_helpers();
    test_reject_reserved_packet_classes();
    test_reject_invalid_inputs();
    test_public_test_vectors();

    puts("mtrojan protocol tests passed");
    return 0;
}

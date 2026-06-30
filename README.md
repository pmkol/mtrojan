# mtrojan

`mtrojan` is a micro trojan 0-RTT relay protocol codec library designed
as a high-performance socks5 replacement.

It refines trojan's lower-level relay idea into a compact binary bootstrap for
high-performance `A -> B -> target` forwarding, avoiding the extra proxy
handshake round trips that traditional socks5-style relay paths require.

This repository contains the protocol wire-format codec. Runtime behavior such
as sockets, connection pools, replay caches, and protocol sniffing belongs to
the program that embeds this library.

## Design Goals

- Replace the socks5 relay handshake with a smaller 0-RTT bootstrap that
  carries target metadata and the first payload together.
- Support both UDP in TCP and native UDP relay paths.
- Support a keyless fast path and a keyed mode for encrypted bootstrap metadata,
  TLS ClientHello / QUIC Initial protection, and optional protection for the
  full flow of traffic such as plain DNS.

## Protocol Comparison

| Property | socks5 | mtrojan no_key | mtrojan key |
|:---|:---|:---|:---|
| Proxy handshake | ≥ 2 RTT | 0 RTT | 0 RTT |
| Credential | Optional, plaintext | None | PSK not sent |
| Target metadata | Plaintext | Plaintext | Encrypted |
| Bootstrap tamper protection | None | None | AEAD tag |
| Replay defense | None | None | Epoch + nonce cache |
| Default data protection | None, raw relay | None, raw relay | Protocol-aware protection |
| UDP transfer | ASSOCIATE | UDP in TCP / native UDP relay | UDP in TCP / native UDP relay |
| TLS / QUIC | Raw relay | Raw relay | ClientHello / QUIC Initial encrypted |
| Plain DNS | Raw relay | Raw relay | Full protection |
| Other traffic | Raw relay | Raw relay | Bootstrap encrypted, full protection optional |

## Protocol Codec Scope

This library provides:

- `mode no_key` TCP bootstrap codec.
- `mode no_key` UDP native init/data codec.
- `mode key` TCP bootstrap codec with caller-provided crypto callbacks.
- `mode key` UDP native init codec with caller-provided crypto callbacks.
- UDP in TCP frame codec.
- Address encoding for IPv4, IPv6, and domain targets.
- Generic key-mode protect/unprotect helpers for `[nonce][ciphertext][tag]`
  bootstrap blocks.
- UDP key-mode nonce class helpers.
- Protocol limit constants for bootstrap payload, key plaintext, and safe UDP
  datagram sizing.

## Runtime Integration Responsibilities

Programs that embed `mtrojan` should implement the runtime pieces appropriate
for their deployment:

- socket I/O and event-loop integration
- connection-pool reuse on the `A-B` path
- UDP native session table and expiration
- nonce generation and nonce replay cache
- `epoch` calculation and replay-window validation
- crypto provider for `mt_key_crypto_t`, such as PSK + HKDF-SHA256 +
  AES-128-GCM
- protocol sniffing and policy decisions for TLS, QUIC, DNS, and generic
  traffic

Those pieces are intentionally outside the codec so the same protocol library
can be embedded by nginx modules, standalone proxies, test tools, or other
programs without imposing a runtime model.

## Integration Notes

The public API is declared in `include/mtrojan.h`.

The codec returns `MT_OK`, `MT_ERR_INVALID`, `MT_ERR_AGAIN`, or
`MT_ERR_NO_SPACE`. Key mode requires a caller-provided `mt_key_crypto_t` with
`seal` and `open` callbacks.

For stream-oriented TCP no_key bootstrap, the wire format has no payload length
field. The decoder consumes only the metadata header and treats the remaining
bytes in the supplied buffer as bootstrap payload. The runtime decides how many
bytes to pre-read as first payload; later bytes are raw relay data.

TCP key bootstrap has `ciphertext_len`, so it can be framed on a stream. UDP
bootstrap/data packets are bounded by the datagram or frame that carries them.

## Wire Formats

### Common Fields

Command field:

```text
0x01 = connect
0x03 = associate
```

Command meaning:

- `connect`: bootstrap creates a normal TCP relay session
- `associate`: bootstrap creates a TCP stream carrying UDP in TCP frames

Flow protection field:

```text
0x00 = bootstrap_protect
0x01 = handshake_protect
0x02 = full_protect
```

`flow_protection` has one value space but two on-wire carriers. TCP bootstrap
plaintext and UDP key bootstrap plaintext carry it as a standalone 1-byte
field. Native UDP no_key init packets carry it in the low 6 bits of
`class_flow_protection`; the top 2 bits carry the packet class.

Flow protection meaning:

- `bootstrap_protect`: protect only the bootstrap in key mode, then raw relay
- `handshake_protect`: protect bootstrap plus TLS ClientHello or QUIC Initial
  material, then raw relay
- `full_protect`: keep the whole flow inside the protected A-B path

Profiles that require a protected path, such as `handshake_protect` and
`full_protect`, require key mode at runtime. In `mode no_key`, only
`bootstrap_protect` is valid on the wire; `handshake_protect` and
`full_protect` are malformed because `no_key` has no protected path.

Opaque byte strings:

- `nonce` and `flow_id` are transmitted as-is after their required packet-class
  bits are applied.
- They are not interpreted as integers and have no byte-order conversion.

Address fields:

```text
[atyp:1B][addr_len:1B][addr][port:2B]
```

`atyp` values:

```text
0x01 = IPv4
0x03 = domain
0x04 = IPv6
```

Rules:

- IPv4 uses `addr_len = 4`
- IPv6 uses `addr_len = 16`
- domain uses `1 <= addr_len <= 255`
- `port` is big-endian

### Key Mode Wrapper

Key-mode bootstrap wrappers are:

TCP key bootstrap:

```text
[nonce:12B][ciphertext_len:2B][ciphertext][tag:16B]
```

UDP key bootstrap:

```text
[nonce:12B][ciphertext][tag:16B]
```

`ciphertext_len` is used only by TCP key bootstrap. It is a big-endian
unsigned 16-bit integer and counts only the `ciphertext` bytes.
Although the field can represent up to 65535 bytes, valid TCP key bootstrap
ciphertext length is still limited by `MT_KEY_PLAIN_MAX`. AES-GCM does not
expand the plaintext into the ciphertext; the authentication tag is carried in
the separate `tag` field.

The encrypted plaintext depends on the bootstrap family.

TCP key bootstrap plaintext:

```text
[epoch:4B][cmd][flow_protection][atyp][addr_len][addr][port][payload]
```

UDP key bootstrap plaintext:

```text
[epoch:4B][flow_protection][flow_id:8B][atyp][addr_len][addr][port][payload]
```

In key mode, `cmd` is inside the encrypted TCP plaintext only. It is not sent
as a cleartext field outside the key-mode wrapper. UDP key bootstrap does not
carry `cmd`; the UDP packet class identifies the UDP path.

### Bootstrap Formats

TCP no_key bootstrap:

```text
[cmd][flow_protection][atyp][addr_len][addr][port][payload]
```

TCP key bootstrap uses the key-mode wrapper defined above; see Key Mode
Wrapper for the encrypted plaintext layout.

Native UDP bootstrap/init is carried by the native UDP packet family; see
Native UDP Packets.

### UDP in TCP

This wire format is used by the default `udp_native off` runtime path. The
optional `udp_native on` path uses the native UDP packet format below
instead.

The UDP in TCP path is selected by a TCP bootstrap with `cmd = associate`.
After that bootstrap, the same TCP stream carries UDP in TCP frames. Native UDP
init and data packets do not carry `cmd` because their UDP packet class already
identifies the native UDP path.

```text
[frame_len:2B][atyp][addr_len][addr][port][payload]
```

`frame_len` is a big-endian unsigned 16-bit length of the bytes after the
`frame_len` field:

```text
frame_len = len([atyp][addr_len][addr][port][payload])
```

It does not include the 2-byte `frame_len` field itself.

### Native UDP Packets

This wire format is used by the optional `udp_native on` runtime path.

mtrojan native UDP packets use the top 2 bits of the first octet as a packet class:

```text
00 = data packet
10 = init packet
01 = reserved
11 = reserved
```

Reserved or unknown packet classes are malformed. Native UDP runtimes should
silently drop those datagrams; codec decoders return `MT_ERR_INVALID`.

No_key init packet:

```text
[class_flow_protection][flow_id:8B][atyp][addr_len][addr][port][payload]
```

Key init packet:

```text
[nonce:12B][ciphertext(epoch|flow_protection|flow_id|atyp|addr_len|addr|port|payload)][tag:16B]
```

Generic data packet in both no_key and key mode:

```text
[flow_id:8B][payload]
```

Generic native UDP data uses `[flow_id][payload]` for lightweight session
demux.

`class_flow_protection`:

```text
top 2 bits = 10
low 6 bits = flow_protection
```

`flow_id` is generated by the sender that creates a native UDP session. It is
8 bytes wide, but `flow_id[0]` must keep its top 2 bits as `00`, so it has 62
bits of random entropy instead of 64. Generic native UDP data packets carry
`flow_id`.

The sender should generate `flow_id` from a CSPRNG and keep it unique among
active local UDP sessions that share the same demux scope. The receiver should
use `flow_id` together with the transport/session context as the demux key. The
required uniqueness domain is that demux scope, not the whole listener or
process. If an init packet would collide with an active session in the same
demux scope, the runtime should drop or reject it without a distinguishable
protocol error.

Use `mt_flow_id_prepare()` before encoding caller-generated flow IDs. It clears
the top 2 bits of `flow_id[0]`; it does not generate randomness or check
session-table uniqueness.

### Native UDP Runtime Data Paths

The native UDP packet class rules above apply only to mtrojan-encoded native
UDP packets. A runtime may also maintain a raw native UDP data path for QUIC
sessions established by a key-mode UDP bootstrap with
`flow_protection = handshake_protect`.

Runtime receive order should be:

1. if the datagram's transport tuple maps to exactly one established raw QUIC
   session, treat the entire datagram as raw QUIC payload
2. otherwise, parse it as an mtrojan native UDP packet using the packet class
   bits
3. if the packet class is reserved or unknown, silently drop it as malformed

The raw QUIC data path is:

```text
QUIC raw datagram:
    [payload]
```

In that path, the raw datagram does not carry `flow_id` and does not use the
mtrojan UDP packet class bits. If the runtime cannot map raw datagrams to
exactly one session, it must either use the generic `[flow_id][payload]` path
for that session or drop the datagram by policy.

### Key Mode Crypto

The library does not hard-code a crypto backend. Callers provide an
`mt_key_crypto_t` with `seal` and `open` callbacks. The preferred deployment
construction is still:

```text
session_key =
    HKDF-SHA256(
        salt = "mtrojan-aead",
        ikm  = PSK,
        info = nonce
    )[:16]

ciphertext, tag =
    AES-128-GCM(
        key = session_key,
        nonce = 0,
        plaintext = plain_block,
        aad = ""
    )
```

The HKDF salt is the ASCII bytes of the literal string `mtrojan-aead`, not a
hex-decoded string. HKDF `info` is the wire nonce bytes transmitted on the
bootstrap, with no byte-order conversion.

The fixed AES-GCM nonce value of `0` is safe only because every bootstrap uses
a fresh `session_key` derived from the `PSK` and the unique wire `nonce`.
AES-GCM nonce uniqueness is scoped to the `(session_key, gcm_nonce)` pair, so
this construction relies on never deriving the same `session_key` twice under
the same `PSK`.

`epoch` is encoded as a big-endian 4-byte unsigned integer:

```text
epoch = floor(unix_seconds / epoch_window_seconds)
```

The default `epoch_window_seconds` value is `30`.

Epoch acceptance is a runtime policy, not an additional wire field. A runtime
must define `accepted_epoch_skew_windows`, the number of adjacent epoch windows
accepted around the local current epoch. A value of `0` accepts only the current
epoch. Larger values tolerate more clock skew but increase the replay window.
The nonce replay cache must cover every epoch accepted by this policy.

UDP key-mode init packets keep the packet class in the top 2 bits of
`nonce[0]`:

```text
nonce[0] = (random[0] & 0x3f) | 0x80
```

Use `mt_key_udp_nonce_prepare()` before encoding caller-generated UDP init
nonces, or let `mt_encode_key_udp_init()` normalize the nonce internally.

Because the top 2 bits of `nonce[0]` carry the packet class, UDP key-mode init
nonces have 94 bits of random entropy instead of 96. CSPRNG-generated nonces
are acceptable for normal deployments. High-throughput deployments should
prefer an explicit uniqueness strategy, such as a per-instance unique prefix
combined with a persisted counter. Counter-based nonce generators must not
reset across restart, worker respawn, or multi-instance deployment under the
same `PSK`.


## Security Semantics

The codec validates wire-format structure, but it does not implement runtime
security state.

`mode no_key` provides no client authentication. It must be protected by
network-layer controls such as private links, firewall rules, or source
allowlists. Exposing `no_key` to untrusted clients makes the receiver an open
relay.

Caller responsibilities:

- generate unique nonces for each key-mode bootstrap
- define an epoch acceptance policy before accepting key-mode bootstraps
- keep a nonce replay cache for every epoch accepted by that policy
- validate decrypted `epoch` against the runtime clock and acceptance policy
- treat decrypt failure, tag failure, stale epoch, replayed nonce, and malformed
  metadata as the same external failure

Recommended external behavior:

- TCP: close the transport connection without a distinguishable protocol error
- UDP: silently drop invalid datagrams and let the runtime apply rate limits

In `mode key`, the bootstrap block is always protected. Later protection
depends on the `flow_protection` value defined in Common Fields:

- `bootstrap_protect`: bootstrap metadata and bootstrap payload are protected,
  then raw relay
- `handshake_protect`: bootstrap plus TLS ClientHello or QUIC Initial material
  is protected, then raw relay
- `full_protect`: the whole flow stays inside the protected A-B path

Later bytes outside the selected protected path rely on the original
application protocol or on a higher-level runtime policy.

In native UDP relay mode, generic later data packets are `[flow_id:8B][payload]`
without encryption or authentication. Anyone who observes the cleartext
`flow_id` can inject packets into that UDP relay session. QUIC raw datagrams
after `handshake_protect` are no longer wrapped by mtrojan and rely on QUIC's
own packet protection.

## Limits

The public constants define the implementation limits used by this codec:

```text
MT_BOOTSTRAP_PAYLOAD_MAX = 16384
MT_KEY_PLAIN_MAX         = 32768
MT_UDP_DATAGRAM_SAFE_MAX = 1200
```

- `MT_BOOTSTRAP_PAYLOAD_MAX` is the maximum bootstrap `payload` field length.
  It does not include `cmd`, `flow_protection`, address fields, nonce,
  ciphertext, or tag overhead.
- `MT_KEY_PLAIN_MAX` is the maximum complete key-mode plaintext block length.
  It includes `epoch`, `cmd` for TCP, `flow_protection`, optional `flow_id`,
  address fields, and bootstrap payload before AEAD encryption.
- Key-mode bootstraps must satisfy both limits: `payload_len` must not exceed
  `MT_BOOTSTRAP_PAYLOAD_MAX`, and the complete plaintext block must not exceed
  `MT_KEY_PLAIN_MAX`.
- `MT_UDP_DATAGRAM_SAFE_MAX` is a recommended complete native UDP relay
  datagram sizing target after mtrojan UDP headers are considered. It is not a
  payload maximum and not a transport MTU discovery mechanism.

## Build

```sh
make
make test
```

## Test Vectors

All byte values in this section are hexadecimal. These vectors are intended for
independent implementation checks. They use the preferred key-mode construction
from Key Mode Crypto when `session_key`, `ciphertext`, and `tag` are shown.
For UDP key bootstrap, the nonce used as HKDF info and as the AES-GCM context
is the normalized wire nonce after the packet-class bits are applied, not the
caller's input nonce.

### Vector 1: TCP no_key Bootstrap

Input:

```text
cmd             = connect
flow_protection = bootstrap_protect
addr            = IPv4 1.2.3.4
port            = 443
payload         = 68656c6c6f
```

Expected wire:

```text
010001040102030401bb68656c6c6f
```

### Vector 2: Native UDP no_key Init

Input:

```text
flow_protection = bootstrap_protect
input_flow_id   = c122334455667788
addr            = IPv4 1.2.3.4
port            = 53
payload         = 646e73
```

Expected prepared flow ID:

```text
0122334455667788
```

Expected wire:

```text
8001223344556677880104010203040035646e73
```

### Vector 3: Native UDP Data

Input:

```text
flow_id = 0122334455667788
payload = 71756963
```

Expected wire:

```text
012233445566778871756963
```

### Vector 4: TCP key Bootstrap

Input:

```text
PSK             = 746573742070736b20313233
nonce           = 000102030405060708090a0b
epoch           = 01020304
cmd             = connect
flow_protection = handshake_protect
addr            = domain example.com
port            = 443
payload         = 68656c6c6f
```

Expected plaintext:

```text
010203040101030b6578616d706c652e636f6d01bb68656c6c6f
```

Expected session key:

```text
78a40269279f651f6689db6a344a0e20
```

Expected ciphertext:

```text
0212290ac4041f48dd18cd7cdbc9393a8c1ee2b41adc913ae17f
```

Expected tag:

```text
8226741b34ba8b3b871057ea594ea707
```

Expected wire:

```text
000102030405060708090a0b001a0212290ac4041f48dd18cd7cdbc9393a8c1ee2b41adc913ae17f8226741b34ba8b3b871057ea594ea707
```

### Vector 5: UDP key Bootstrap

Input:

```text
PSK             = 746573742070736b20313233
input_nonce     = 01112233445566778899aabb
epoch           = 01020304
flow_protection = full_protect
flow_id         = 0122334455667788
addr            = IPv4 1.2.3.4
port            = 53
payload         = 646e73
```

Expected normalized nonce:

```text
81112233445566778899aabb
```

Expected plaintext:

```text
010203040201223344556677880104010203040035646e73
```

Expected session key:

```text
840dcddd428802a3b7618994387f6a34
```

Expected ciphertext:

```text
6c89b5fcb16f159698024928236e23ee33c55a72befa8ddf
```

Expected tag:

```text
d7d2aee47fefc1300ca3d3f046b784d8
```

Expected wire:

```text
81112233445566778899aabb6c89b5fcb16f159698024928236e23ee33c55a72befa8ddfd7d2aee47fefc1300ca3d3f046b784d8
```

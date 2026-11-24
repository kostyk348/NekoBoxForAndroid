# hedge

A local CONNECT tunnel that **replays a failed TLS handshake on behalf of the application**.

## Why

On the author's machine TCP connects fine, but the server drops TLS in the middle of the handshake
in waves — 40–60 % of attempts, visible in the logs as:

```
error: failed retrieving file 'system.db' from mirror2.artixlinux.org :
TLS connect error: error:0A000126:SSL routines::unexpected eof while reading
```

`pacman`, `gh`, `curl` and the Gmail API treat this as "network unreachable" and fail, although the
problem is one lost byte at the very beginning of a session.

## The idea

Until the server has sent **a single byte**, the connection means nothing: the client's ClientHello
is stateless, so it can simply be sent again on a new connection. `hedge` buffers everything the
client managed to send, and when the connection dies before the first response byte it dials again
and repeats exactly those bytes. The application never notices — the network is just a little
slower.

Once the server answers with even one byte, the tunnel switches to plain copying and stops
retrying: replaying the middle of a stream is not safe.

## Usage

```bash
hedge --listen 127.0.0.1:8899 --retries 6

# check
https_proxy=http://127.0.0.1:8899 curl -sS https://api.github.com

# pacman: /etc/pacman.conf
XferCommand = /usr/bin/curl -L -f -C - --retry 3 --connect-timeout 10 \
              -x http://127.0.0.1:8899 -o %o %u

# gh / gmail / any HTTPS client
export HTTPS_PROXY=http://127.0.0.1:8899
```

## Measurements (real, on this machine)

A test server dropping 40 % of connections, 30 requests:

| Mode | Succeeded | Time |
|---|---|---|
| direct | 18 / 30 (60 %) | 170 ms |
| hedge, 5 retries, 120 ms backoff | 29 / 30 (97 %) | 4405 ms |
| hedge, 6 retries, 40 ms backoff | **30 / 30 (100 %)** | 1095 ms |

`hedge` printed ten `handshake retried` lines — ten connections were saved by a replay rather than
by luck.

Integrity against a live mirror:

```
tunnel.db  308447 bytes  sha256 d04d148d2223…  identical to the direct download
```

## Limits (honest)

- It only helps **before the first response byte**. A drop in the middle of a download is a resume
  problem (`curl -C -`), not a replay one.
- It does not terminate TLS: no caching, no certificate substitution — and it must not.
- Plain HTTP without CONNECT is not proxied; for HTTPS that is enough.
- One thread per tunnel, no warm connection pool: the win is reliability, not first-byte latency.
- Replaying a handshake is legitimate only for an idempotent session start; protocols where the
  client sends state before the server answers are out of scope.

## Verified

- a flaky server that silently kills the first connection → the client got its answer on the second
  attempt, and the replayed request bytes are visible in the server log;
- a 40 % loss server → 18/30 direct versus 30/30 through the tunnel;
- live HTTPS (`api.github.com`, `mirror2.artixlinux.org`) → 200, file byte-for-byte identical.

MIT licence. No dependencies: Rust std only (`cargo build --release --offline`).

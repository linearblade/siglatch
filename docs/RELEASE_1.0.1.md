# Siglatch 1.0.1

Released: 2026-10-05

Use tag `1.0.1` for the maintained 1.0 daemon. The original `1.0` tag remains
unchanged. Current `master` is `2.0-dev` and already rejects failed signature
authorization before dispatch.

## Fix

The 1.0 structured-packet handler logged an invalid user HMAC but continued
to dispatch an enabled, permitted action. Version 1.0.1 returns immediately
from that failure branch. The change is `return 0;` and a log newline in
`src/siglatch/handle_packet.c`.

Packet encryption, packet format, keys, action IDs and ordinary Knocker
commands remain compatible. Valid requests still execute; dummy, wrong-key
and missing HMAC requests cannot invoke a structured action constructor.

## Build and update

```sh
git fetch origin tag 1.0.1
git checkout --detach 1.0.1
make clean all
```

Supply the OpenSSL 3 include/library flags appropriate to your system. Back up
the installed daemon, install only the newly built `siglatchd`, restart its
service and verify valid requests. Preserve the existing configuration, keys
and customized scripts. Running the full installer can overwrite those files.
The client does not require replacement for this fix.

## Regression

```sh
python3 tests/auth_dispatch.py
# For a custom OpenSSL installation:
python3 tests/auth_dispatch.py --openssl-prefix /path/to/openssl-3
```

The test builds a real daemon/client with disposable keys and a loopback-only
marker constructor. It checks valid requests before and after three invalid
HMAC controls, asserts the invalid controls were received, and verifies that
none executed the constructor. It has passed on macOS and Linux/OpenSSL 3.

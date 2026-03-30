# Normalize Design Note

`normalize` is intentionally a simple parser seam for now:

- raw ingress in
- normalized packet out
- return `1` for success, `0` for failure

Longer term, stateful backends like QUIC or HTTP/3 may need a richer tagged
envelope instead of a plain packet. That future shape may include:

- ingress variants
- normalized transport units
- outbound / serialize variants
- control / timeout / reset events

If we get there, prefer a tagged union or envelope type so the caller never has
to guess which kind of transport object it is holding.

# dense

An attempt to write a deserializer for the DNS wire format described in [RFC 1035](https://tools.ietf.org/html/rfc1035), with minimal dependencies. `docopt` and `serde` are used for command-line parsing; tokio for asynchrony and UDP transport.

## Usage

```sh
$ cargo build
$ cargo run google.ca
```

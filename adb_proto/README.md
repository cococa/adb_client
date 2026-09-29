# adb_proto

Sans-IO core of the ADB wire protocol: packet codec, RSA authentication,
connection handshake, stream multiplexing with per-stream flow control, and
`sync:` file-transfer framing.

The crate performs no I/O, spawns no threads and reads no clock. A driver
sends every packet from `Session::poll_transmit`, feeds received bytes to
`Session::handle_input`, and handles `Session::poll_event`. The same logic
therefore runs over blocking native USB and over asynchronous WebUSB.

Key storage belongs to the caller: pass an `AdbKey` loaded from PKCS#8 PEM.

It builds for `wasm32-unknown-unknown`:

```sh
cargo build -p adb_proto --target wasm32-unknown-unknown
```

# IHNET2

Complete rewrite of my original [ihnet](https://github.com/Logan-010/ihnet) tool
that fixes bugs and improves on many shortcomings.

New and improved CLI & routes system (forward multiple ports on one running
process using one identity!), along with stream multiplexing (many UDP
connections over one channel!) and general performance improvements.

## What?

IHNET2 is a simple, fast, and secure (UDP, TCP, or both!) port forwarder that
allows one computer to connect to another even behind a NAT & a private IP.

Supports secure authentication (Argon2id based key-derivation) so not just
anyone can connect to your ports.

## Features

- **NAT Traversal**: Connects computers behind NATs and private IPs
- **Secure Authentication**: Uses Argon2id-based key derivation for secure
  connections
- **Multi-Protocol Support**: Works with TCP, UDP, or both protocols
  simultaneously
- **Stream Multiplexing**: Multiple connections over one channel
- **Flexible Routing**: Forward multiple ports using a single identity
- **Modern Architecture**: Built with Rust and leveraging iroh for connectivity

## Installation

To build IHNET2 from source:

```sh
cargo build --release
```

The binary will be available in `target/release/ihnet2`.

## Usage

### Start the daemon

```sh
ihnet2 daemon
```

### Create a route to share a local service

```sh
ihnet2 route create 127.0.0.1:8080 --auth mypassword
```

This will output a ticket you can use to connect from another machine.

### Add a route using a ticket

```sh
ihnet2 route add <ticket>
```

### Import/export routes

# Export a route to file

```sh
ihnet2 route export 127.0.0.1:8080 --to myroute.json
```

# Import a route from file

```sh
ihnet2 route import myroute.json
```

## Configuration

IHNET2 uses a configuration file for settings. The default location is
`~/.ihnet2/config.toml` or you can specify a custom location with the -c flag.

## Security

- Authentication is handled via Argon2id key derivation
- All communication is encrypted using iroh's secure transport
- Port sharing is controlled through authentication tokens

## License

This project is licensed under the Unlicense. See the [UNLICENSE](UNLICENSE)
file for details.

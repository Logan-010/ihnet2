# IHNET2

Complete rewrite of my original [ihnet](https://github.com/Logan-010/ihnet) tool
that fixes bugs and improves on many shortcomings.

New and improved CLI & routes system (forward multiple ports on one running
process using one identity!), along with stream multiplexing (many UDP
connections over one channel!) and general performance improvements.

# What?

`IHNET2` is a simple, fast, and secure (UDP, TCP, or both!) port forwarder that
allows one computer to connect to another even behind a NAT & a private IP.

Supports secure authentication (Argon2id based key-derivation) so not just
anyone can connect to your ports.

#TODO fix routing (client connects, sends id, udp/tcp, continue from there. not
client connects, sends id, server sends tcp/udp packets) fix udp packet
forwarding

pub const ALPN: &[u8] = concat!("/ihnet2/", env!("CARGO_PKG_VERSION")).as_bytes();
pub const HANDSHAKE: &[u8] = b"I never would've thought this possible, these feelings that overwhelm me, but as the hate diminishes it's restored with a life, a life with new meaning";

pub const AUTH_HEADER: &[u8] = b"AUTH";
pub const PUBL_HEADER: &[u8] = b"PUBL";

pub const TCP_HEADER: &[u8] = b"TCP";
pub const UDP_HEADER: &[u8] = b"UDP";

pub const HEADER_SIZE: usize = 3;

pub const BUFFER_SIZE: usize = 4 * 1024;

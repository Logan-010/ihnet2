use crate::net::types::{TCP_PROTOCOL, UDP_PROTOCOL};
use color_eyre::eyre::bail;

pub fn build_alpn(protocol: &str, id: &str) -> color_eyre::Result<Vec<u8>> {
    if protocol != UDP_PROTOCOL && protocol != TCP_PROTOCOL {
        bail!("Protocol must be \"udp\" or \"tcp\"");
    }

    if id.len() != 64 {
        bail!("Invalid ID");
    }

    let mut out = Vec::new();
    out.extend_from_slice(concat!("/ihnet2/", env!("CARGO_PKG_VERSION"), "/").as_bytes());
    out.extend_from_slice(protocol.as_bytes());
    out.extend_from_slice(b"/");
    out.extend_from_slice(id.as_bytes());

    Ok(out)
}

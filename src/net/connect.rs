use crate::{
    config::ConnectRoute,
    net::{
        AUTH_HEADER, BUFFER_SIZE, HANDSHAKE, HEADER_SIZE, PUBL_HEADER, Stream, TCP_PROTOCOL,
        UDP_PROTOCOL, build_alpn,
    },
};
use color_eyre::eyre::bail;
use iroh::{Endpoint, endpoint::Connection};
use std::{
    collections::HashMap,
    hash::{DefaultHasher, Hash, Hasher},
    net::SocketAddr,
};
use tokio::{
    io,
    net::{TcpListener, TcpStream, UdpSocket},
    select, task,
};
use tokio_util::sync::CancellationToken;

pub async fn connect(
    endpoint: Endpoint,
    route: ConnectRoute,
    cancel: CancellationToken,
) -> color_eyre::Result<()> {
    if route.tcp.unwrap_or(true) {
        let ct = cancel.child_token();
        let e = endpoint.clone();
        let r = route.clone();
        let ct2 = ct.child_token();
        task::spawn(async move {
            select! {
                _ = ct.cancelled() => {},
                res = task_tcp(e, r, ct2) => if let Err(e) = res {
                    tracing::warn!("Failed to connect to TCP: {}", e);
                }
            }
        });
    }

    if route.udp.unwrap_or(true) {
        let ct = cancel.child_token();
        let e = endpoint.clone();
        let r = route.clone();
        task::spawn(async move {
            select! {
                _ = ct.cancelled() => {},
                res = task_udp(e, r) => if let Err(e) = res {
                    tracing::warn!("Failed to connect to UDP: {}", e);
                }
            }
        });
    }

    Ok(())
}

async fn authenticate(conn: Connection, auth: Option<&str>) -> color_eyre::Result<Connection> {
    let mut rx = conn.accept_uni().await?;

    let mut header = [0u8; HEADER_SIZE];
    rx.read_exact(&mut header).await?;

    if header == PUBL_HEADER {
        Ok(conn)
    } else if header == AUTH_HEADER {
        if auth.is_none() {
            bail!("Endpoint requires auth");
        }

        let auth = auth.unwrap();

        let mut tx = conn.open_uni().await?;

        tx.write_all(&(auth.len() as u32).to_le_bytes()).await?;
        tx.write_all(auth.as_bytes()).await?;

        Ok(conn)
    } else {
        bail!("Unknown header");
    }
}

async fn task_tcp(
    endpoint: Endpoint,
    route: ConnectRoute,
    cancel: CancellationToken,
) -> color_eyre::Result<()> {
    let socket = TcpListener::bind(
        route
            .address
            .unwrap_or("127.0.0.1:0".parse().expect("Valid address")),
    )
    .await?;

    tracing::info!(
        "Route \"{}\" ({}) reachable at TCP \"{}\"",
        route.name.as_deref().unwrap_or("unknown"),
        route.id,
        socket.local_addr()?
    );

    loop {
        let (stream, from) = match socket.accept().await {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!("Failed to accept connection: {}", e);
                continue;
            }
        };

        tracing::debug!("Incoming connection from \"{}\"", from);

        let ct = cancel.child_token();
        let e = endpoint.clone();
        let r = route.clone();
        task::spawn(async move {
            select! {
                _ = ct.cancelled() => {},
                res = task_tcp_inner(e, r, stream) => if let Err(e) = res {
                    tracing::warn!("Error forwarding TCP: {}", e);
                }
            }
        });
    }
}

async fn task_tcp_inner(
    endpoint: Endpoint,
    route: ConnectRoute,
    mut socket: TcpStream,
) -> color_eyre::Result<()> {
    let alpn = build_alpn(TCP_PROTOCOL, &route.id)?;
    let base_conn = endpoint.connect(route.public_key, &alpn).await?;

    let conn = authenticate(base_conn, route.auth.as_deref()).await?;

    let (tx, mut rx) = conn.accept_bi().await?;
    rx.read_exact(&mut [0u8; HANDSHAKE.len()]).await?;

    let mut stream = Stream { send: tx, recv: rx };

    io::copy_bidirectional(&mut socket, &mut stream).await?;

    Ok(())
}

async fn task_udp(endpoint: Endpoint, route: ConnectRoute) -> color_eyre::Result<()> {
    let alpn = build_alpn(UDP_PROTOCOL, &route.id)?;
    let base_conn = endpoint.connect(route.public_key, &alpn).await?;

    let conn = authenticate(base_conn, route.auth.as_deref()).await?;

    let (mut tx, mut rx) = conn.accept_bi().await?;
    rx.read_exact(&mut [0u8; HANDSHAKE.len()]).await?;

    let socket = UdpSocket::bind(
        route
            .address
            .unwrap_or("127.0.0.1:0".parse().expect("Valid address")),
    )
    .await?;

    tracing::info!(
        "Route \"{}\" ({}) reachable at UDP \"{}\"",
        route.name.as_deref().unwrap_or("unknown"),
        route.id,
        socket.local_addr()?
    );

    let mut ids: HashMap<u64, SocketAddr> = HashMap::new();
    let mut buf = [0u8; BUFFER_SIZE];
    let mut id_bytes = [0u8; 8];

    loop {
        select! {
            recv_res = socket.recv_from(&mut buf) => {
                let (n, from) = recv_res?;

                let mut hasher = DefaultHasher::new();
                from.ip().hash(&mut hasher);
                let id = hasher.finish();

                ids.insert(id, from);

                tx.write_all(&id.to_le_bytes()).await?;
                tx.write_all(&(n as u32).to_le_bytes()).await?;
                tx.write_all(&buf[..n]).await?;
            }

            stream_res = rx.read_exact(&mut id_bytes) => {
                stream_res?;

                let id = u64::from_le_bytes(id_bytes);

                let mut length_bytes = [0u8; 4];
                rx.read_exact(&mut length_bytes).await?;
                let length = u32::from_le_bytes(length_bytes) as usize;
                if length > BUFFER_SIZE {
                    bail!("Read too big");
                }
                rx.read_exact(&mut buf[..length]).await?;

                if let Some(addr) = ids.get(&id) {
                    socket.send_to(&buf[..length], addr).await?;
                }
            }
        }
    }
}

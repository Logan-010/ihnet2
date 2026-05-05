use crate::{
    config::{Config, ConnectRoute, ForwardRoute},
    net::{
        ALPN, Stream,
        types::{
            AUTH_HEADER, BUFFER_SIZE, HANDSHAKE, HEADER_SIZE, PUBL_HEADER, TCP_HEADER, UDP_HEADER,
        },
    },
};
use argon2::{
    Argon2, PasswordHash, PasswordHasher, PasswordVerifier,
    password_hash::{SaltString, rand_core::OsRng},
};
use color_eyre::eyre::{Context, ContextCompat, bail};
use iroh::{
    Endpoint,
    address_lookup::MdnsAddressLookup,
    endpoint::{Connection, presets},
};
use std::{
    collections::HashMap,
    hash::{DefaultHasher, Hash, Hasher},
    net::SocketAddr,
};
use tokio::{
    io::{self, AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    select,
    sync::mpsc,
    task,
};
use tokio_util::sync::CancellationToken;

pub async fn task(config: Config, cancel: CancellationToken) -> color_eyre::Result<()> {
    let key = config.key().context("Invalid identity")?;

    let endpoint = if config.local_only.unwrap_or(false) {
        Endpoint::builder(presets::Empty)
    } else {
        Endpoint::builder(presets::N0)
    }
    .address_lookup(MdnsAddressLookup::builder().build(key.public())?)
    .alpns(vec![ALPN.to_vec()])
    .secret_key(key)
    .bind()
    .await?;

    if let Some(routes) = config.connect {
        for route in routes {
            let e = endpoint.clone();
            let ct = cancel.child_token();
            let ct2 = ct.child_token();

            task::spawn(async move {
                loop {
                    let t = ct.clone();
                    select! {
                        _ = t.cancelled() => break,
                        connect_res = connect(route.clone(), e.clone(), ct2.clone()) => if let Err(e) = connect_res {
                            tracing::warn!("Route connection failed: {}", e);
                            ct2.cancel();
                        }
                    }
                }
            });
        }
    }

    let mut routing = HashMap::new();

    if let Some(routes) = config.forward {
        for route in routes {
            let (tx, rx) = mpsc::channel(10);

            let raw_id = hex::decode(&route.id).context("Invalid route id")?;
            if raw_id.len() != 32 {
                bail!("Invalid route id");
            }
            let mut id = [0u8; 32];
            id.clone_from_slice(&raw_id);

            routing.insert(id, tx);

            let ct = cancel.child_token();
            task::spawn(async move {
                let ct2 = ct.child_token();
                select! {
                    _ = ct.cancelled() => {},
                    routing_res = routing_handler(route, rx, ct2.clone()) => if let Err(e) = routing_res {
                        tracing::error!("Handler router failed: {}", e);
                        ct2.cancel();
                    }
                }
            });
        }
    }

    select! {
        _ = cancel.cancelled() => {}
        endpoint_res = endpoint_loop(endpoint, routing) => if let Err(e) = endpoint_res {
            tracing::error!("Endpoint failure: {}", e);
        }
    }

    Ok(())
}

async fn connect(
    route: ConnectRoute,
    endpoint: Endpoint,
    cancel: CancellationToken,
) -> color_eyre::Result<()> {
    let conn = endpoint.connect(route.public_key, ALPN).await?;

    let id = hex::decode(&route.id)?;
    if id.len() != 32 {
        bail!("Invalid route id");
    }

    let mut id_tx = conn.open_uni().await?;
    id_tx.write_all(&id).await?;
    id_tx.finish()?;

    let mut auth_rx = conn.accept_uni().await?;

    let mut auth_code = [0u8; 4];
    auth_rx.read(&mut auth_code).await?;

    if auth_code == AUTH_HEADER {
        let password = route.auth.context("Endpoint requires auth")?;

        let mut tx = conn.open_uni().await?;

        tx.write_all(&(password.len() as u32).to_be_bytes()).await?;
        tx.write_all(password.as_bytes()).await?;

        tx.finish()?;
    } else if auth_code == PUBL_HEADER {
        // All good, endpoint does not require auth!
    } else {
        bail!("Unknown auth code");
    }

    // Connect local sockets and forward to/from stream

    if route.tcp.unwrap_or(true) {
        let socket =
            TcpListener::bind(route.address.unwrap_or("127.0.0.1:0".parse().unwrap())).await?;

        tracing::info!(
            "Route \"{}\" ({}) listening on TCP address \"{}\"",
            route.name.as_deref().unwrap_or("unnamed"),
            route.id,
            socket.local_addr()?
        );

        let c = conn.clone();
        let ct = cancel.child_token();
        let ct2 = ct.child_token();
        task::spawn(async move {
            select! {
                _ = ct.cancelled() => {},
                tcp_res = connect_tcp(socket, c, ct2.clone()) => if let Err(e) = tcp_res {
                    tracing::warn!("Failed to forward TCP: {}", e);
                    ct2.cancel();
                }
            }
        });
    }

    if route.udp.unwrap_or(true) {
        let socket =
            UdpSocket::bind(route.address.unwrap_or("127.0.0.1:0".parse().unwrap())).await?;

        tracing::info!(
            "Route \"{}\" ({}) listening on UDP address \"{}\"",
            route.name.as_deref().unwrap_or("unnamed"),
            route.id,
            socket.local_addr()?
        );

        let ct = cancel.child_token();
        let c = conn.clone();
        task::spawn(async move {
            select! {
                _ = ct.cancelled() => {},
                tcp_res = connect_udp(socket, c) => if let Err(e) = tcp_res {
                    tracing::warn!("Failed to forward UDP: {}", e);
                }
            }
        });
    }

    Ok(())
}

async fn connect_tcp(
    listener: TcpListener,
    conn: Connection,
    cancel: CancellationToken,
) -> color_eyre::Result<()> {
    loop {
        let (mut local_stream, from) = listener.accept().await?;

        tracing::debug!("Incoming local connection from {}", from);

        let (mut tx, mut rx) = conn.open_bi().await?;
        tx.write_all(HANDSHAKE).await?;
        let mut handshake = [0u8; HANDSHAKE.len()];
        rx.read_exact(&mut handshake).await?;
        if handshake != HANDSHAKE {
            bail!("Invalid handshake")
        }

        tx.write_all(TCP_HEADER).await?;

        let mut remote_stream = Stream { send: tx, recv: rx };

        tracing::debug!("Opened remote connection");

        let ct = cancel.child_token();

        task::spawn(async move {
            select! {
                _ = ct.cancelled() => {}
                copy_res = io::copy_bidirectional(&mut local_stream, &mut remote_stream) => if let Err(e) = copy_res {
                    tracing::warn!("Error forwarding TCP connection: {}", e);
                }
            }
        });
    }
}

async fn connect_udp(socket: UdpSocket, conn: Connection) -> color_eyre::Result<()> {
    let (mut tx, mut rx) = conn.open_bi().await?;
    tx.write_all(HANDSHAKE).await?;
    let mut handshake = [0u8; HANDSHAKE.len()];
    rx.read_exact(&mut handshake).await?;
    if handshake != HANDSHAKE {
        bail!("Invalid handshake")
    }

    tx.write_all(UDP_HEADER).await?;

    let mut rx_buf = [0u8; BUFFER_SIZE];
    let mut udp_buf = [0u8; BUFFER_SIZE];
    let mut hash_buf = [0u8; 8];

    let mut addresses = HashMap::new();

    loop {
        select! {
            Ok((n, from)) = socket.recv_from(&mut udp_buf) => {
                tracing::debug!("Incoming local packet from {}", from);

                let mut hasher = DefaultHasher::new();
                from.hash(&mut hasher);
                let hash = hasher.finish();

                addresses.insert(hash, from);

                tx.write_all(&hash.to_be_bytes()).await?;
                tx.write_all(&(n as u32).to_be_bytes()).await?;
                tx.write_all(&udp_buf[..n]).await?;
            },
            Ok(_) = rx.read_exact(&mut hash_buf) => {
                let hash = u64::from_be_bytes(hash_buf);

                let mut length_bytes = [0u8; 4];
                rx.read_exact(&mut length_bytes).await?;
                let length = u32::from_be_bytes(length_bytes) as usize;

                if length > BUFFER_SIZE {
                    bail!("Read too big");
                }

                rx.read_exact(&mut rx_buf[..length]).await?;

                if let Some(addr) = addresses.get(&hash) {
                    socket.send_to(&rx_buf[..length], addr).await?;
                }
            }
        }
    }
}

async fn endpoint_loop(
    endpoint: Endpoint,
    routing: HashMap<[u8; 32], mpsc::Sender<Connection>>,
) -> color_eyre::Result<()> {
    while let Some(incoming) = endpoint.accept().await {
        match incoming.await {
            Ok(conn) => {
                let mut id = [0u8; 32];

                let Ok(mut rx) = conn.accept_uni().await else {
                    continue;
                };

                if rx.read_exact(&mut id).await.is_err() {
                    continue;
                }

                if let Some(tx) = routing.get(&id) {
                    tx.send(conn).await?;
                }
            }
            Err(e) => {
                tracing::warn!("Failed to upgrade connection: {}", e);
            }
        }
    }

    Ok(())
}

async fn routing_handler(
    route: ForwardRoute,
    mut rx: mpsc::Receiver<Connection>,
    cancel: CancellationToken,
) -> color_eyre::Result<()> {
    let salt = SaltString::generate(&mut OsRng);
    let auth_hash = match route.auth.as_ref() {
        Some(key) => Some(Argon2::default().hash_password(key.as_bytes(), &salt)?),
        None => None,
    };

    while let Some(conn) = rx.recv().await {
        let Ok(mut tx) = conn.open_uni().await else {
            continue;
        };

        if let Some(hash) = auth_hash.as_ref() {
            if tx.write_all(AUTH_HEADER).await.is_err() {
                continue;
            }

            if tx.finish().is_err() {
                continue;
            }

            if let Err(e) = authenticate(&conn, hash).await {
                tracing::warn!("Auth error: {}", e);
                continue;
            }
        } else {
            if tx.write_all(PUBL_HEADER).await.is_err() {
                continue;
            }

            if tx.finish().is_err() {
                continue;
            }
        }

        let ct = cancel.child_token();
        let ct2 = ct.child_token();
        let rt = route.clone();
        task::spawn(async move {
            select! {
                _ = ct.cancelled() => {},
                forward_res = forward(rt, conn, ct2.clone()) => if let Err(e) = forward_res {
                    tracing::warn!("Failed to forward route: {}", e);
                    ct2.cancel();
                }
            }
        });
    }

    Ok(())
}

async fn authenticate(conn: &Connection, hash: &PasswordHash<'_>) -> color_eyre::Result<()> {
    let mut rx = conn.accept_uni().await?;

    let mut length_bytes = [0u8; 4];
    rx.read_exact(&mut length_bytes).await?;
    let length = u32::from_be_bytes(length_bytes) as usize;
    let mut password = vec![0u8; length];
    rx.read_exact(&mut password).await?;

    Argon2::default().verify_password(&password, hash)?;

    Ok(())
}

async fn forward(
    route: ForwardRoute,
    conn: Connection,
    cancel: CancellationToken,
) -> color_eyre::Result<()> {
    while let Ok((mut tx, mut rx)) = conn.accept_bi().await {
        let mut handshake = [0u8; HANDSHAKE.len()];
        rx.read_exact(&mut handshake).await?;
        if handshake != HANDSHAKE {
            bail!("Invalid handshake");
        }
        tx.write_all(HANDSHAKE).await?;

        let mut header = [0u8; HEADER_SIZE];
        rx.read_exact(&mut header).await?;

        let stream = Stream { send: tx, recv: rx };

        if header == TCP_HEADER {
            let ct = cancel.child_token();
            task::spawn(async move {
                select! {
                    _ = ct.cancelled() => {},
                    tcp_res = forward_tcp(route.address, stream) => if let Err(e) = tcp_res {
                        tracing::warn!("Failed to forward TCP connection: {}", e);
                    }
                }
            });
        } else if header == UDP_HEADER {
            let ct = cancel.child_token();
            let ct2 = ct.child_token();
            task::spawn(async move {
                select! {
                    _ = ct.cancelled() => {},
                    tcp_res = forward_udp(route.address, stream, ct2.clone()) => if let Err(e) = tcp_res {
                        tracing::warn!("Failed to forward UDP connection: {}", e);
                        ct2.cancel();
                    }
                }
            });
        } else {
            bail!("Unknown header");
        }
    }

    Ok(())
}

async fn forward_tcp(addr: SocketAddr, mut stream: Stream) -> color_eyre::Result<()> {
    let mut local_stream = TcpStream::connect(addr).await?;

    io::copy_bidirectional(&mut local_stream, &mut stream).await?;

    Ok(())
}

async fn forward_udp(
    addr: SocketAddr,
    mut stream: Stream,
    cancel: CancellationToken,
) -> color_eyre::Result<()> {
    let mut hash_bytes = [0u8; 8];

    let (tx, mut rx) = mpsc::channel(15);

    loop {
        select! {
            Ok(_) = stream.read_exact(&mut hash_bytes) => {
                let hash = u64::from_be_bytes(hash_bytes);

                let mut length_bytes = [0u8; 4];
                stream.read_exact(&mut length_bytes).await?;
                let length = u32::from_be_bytes(length_bytes) as usize;

                let mut packet = vec![0u8; length];
                stream.read_exact(&mut packet).await?;

                let ct = cancel.child_token();
                let t = tx.clone();
                task::spawn(async move {
                    select! {
                        _ = ct.cancelled() => {},
                        socket_res = forward_udp_socket(hash, t, addr, packet) => if let Err(e) = socket_res {
                            tracing::warn!("Error forwarding UDP socket: {}", e);
                        }
                    }
                });
            }
            Some((hash, packet)) = rx.recv() => {
                stream.write_all(&hash.to_be_bytes()).await?;
                stream.write_all(&(packet.len() as u32).to_be_bytes()).await?;
                stream.write_all(&packet).await?;
            }
        }
    }
}

async fn forward_udp_socket(
    hash: u64,
    tx: mpsc::Sender<(u64, Vec<u8>)>,
    addr: SocketAddr,
    packet: Vec<u8>,
) -> color_eyre::Result<()> {
    let socket =
        UdpSocket::bind("127.0.0.1:0".parse::<SocketAddr>().expect("Valid address")).await?;
    socket.connect(addr).await?;

    socket.send(&packet).await?;

    let mut udp_buf = [0u8; BUFFER_SIZE];

    loop {
        let n = socket.recv(&mut udp_buf).await?;

        tx.send((hash, udp_buf[..n].to_vec())).await?;
    }
}

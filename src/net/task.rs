use crate::{
    config::{Config, ConnectRoute, ForwardRoute},
    net::{
        ALPN,
        types::{
            AUTH_HEADER, BUFFER_SIZE, HANDSHAKE, HEADER_SIZE, PUBL_HEADER, TCP_HEADER, UDP_HEADER,
        },
    },
};
use argon2::{
    Argon2, PasswordHash, PasswordHasher, PasswordVerifier,
    password_hash::{SaltString, rand_core::OsRng},
};
use color_eyre::eyre::{ContextCompat, bail};
use iroh::{
    Endpoint,
    address_lookup::MdnsAddressLookup,
    endpoint::{Connection, VarInt, presets},
};
use std::{collections::HashMap, future, net::SocketAddr};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpStream, UdpSocket},
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

            task::spawn(async move {
                select! {
                    _ = ct.cancelled() => {},
                    connect_res = connect(route, e) => if let Err(e) = connect_res {
                        tracing::warn!("Route connection failed: {}", e);
                    }
                }
            });
        }
    }

    let mut routing = HashMap::new();

    if let Some(routes) = config.forward {
        for route in routes {
            let (tx, rx) = mpsc::channel(10);

            routing.insert(route.id, tx);

            let ct = cancel.child_token();
            task::spawn(async move {
                let ct2 = ct.child_token();
                select! {
                    _ = ct.cancelled() => {},
                    routing_res = routing_handler(route, rx, ct2) => if let Err(e) = routing_res {
                        tracing::error!("Handler router failed: {}", e);
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

async fn connect(route: ConnectRoute, endpoint: Endpoint) -> color_eyre::Result<()> {
    let conn = endpoint.connect(route.public_key, ALPN).await?;

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

    Ok(())
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

                if rx.stop(VarInt::from_u32(0)).is_err() {
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
        let rt = route.clone();
        task::spawn(async move {
            select! {
                _ = ct.cancelled() => {},
                forward_res = forward(rt, conn) => if let Err(e) = forward_res {
                    tracing::warn!("Failed to forward route: {}", e);
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

async fn forward(route: ForwardRoute, conn: Connection) -> color_eyre::Result<()> {
    let udp_socket = match route.udp.unwrap_or(true) {
        true => {
            let socket =
                UdpSocket::bind("0.0.0.0:0".parse::<SocketAddr>().expect("Valid address")).await?;
            socket.connect(route.address).await?;

            Some(socket)
        }
        false => None,
    };
    let mut tcp_socket = match route.tcp.unwrap_or(true) {
        true => Some(TcpStream::connect(route.address).await?),
        false => None,
    };

    let (mut tx, mut rx) = conn.accept_bi().await?;

    tx.write_all(HANDSHAKE).await?;
    let mut handshake = [0u8; HANDSHAKE.len()];
    rx.read_exact(&mut handshake).await?;
    if handshake != HANDSHAKE {
        bail!("Invalid handshake");
    }

    let mut tx_tcp_buf = [0u8; BUFFER_SIZE];
    let mut tx_udp_buf = [0u8; BUFFER_SIZE];
    let mut rx_buf = [0u8; HEADER_SIZE + BUFFER_SIZE];

    loop {
        tokio::select! {
            // UDP packet
            Ok(n) = async {
                if let Some(sock) = udp_socket.as_ref() {
                    sock.recv(&mut tx_udp_buf).await
                } else {
                    future::pending().await
                }
            } => {
                if n == 0 {
                    break;
                }

                tx.write_all(UDP_HEADER).await?;
                tx.write_all(&tx_udp_buf[..n]).await?;
            },
            // TCP packet
            Ok(n) = async {
                if let Some(sock) = tcp_socket.as_mut() {
                    sock.read(&mut tx_tcp_buf).await
                } else {
                    future::pending().await
                }
            } => {
                if n == 0 {
                    break;
                }

                tx.write_all(TCP_HEADER).await?;
                tx.write_all(&tx_tcp_buf[..n]).await?;
            },
            // Stream packet
            Ok(n_res) = rx.read(&mut rx_buf) => {
                let n = n_res.unwrap_or(0);

                if n == 0 {
                    break;
                }

                if n < HEADER_SIZE {
                    bail!("Read too short");
                }

                if &rx_buf[..HEADER_SIZE] == TCP_HEADER {
                    if let Some(sock) = tcp_socket.as_mut() {
                        sock.write_all(&rx_buf[HEADER_SIZE..n]).await?;
                    } else {
                        bail!("TCP packet with no TCP enabled");
                    }
                } else if &rx_buf[..HEADER_SIZE] == UDP_HEADER {
                    if let Some(sock) = udp_socket.as_ref() {
                        sock.send(&rx_buf[HEADER_SIZE..n]).await?;
                    } else {
                        bail!("UDP packet with no UDP enabled");
                    }
                } else {
                    bail!("Invalid header");
                }
            }
        }
    }

    Ok(())
}

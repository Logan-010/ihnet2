use crate::{
    config::ForwardRoute,
    net::{AUTH_HEADER, BUFFER_SIZE, HANDSHAKE, PUBL_HEADER, Stream},
};
use argon2::{
    Argon2, PasswordHash, PasswordHasher, PasswordVerifier,
    password_hash::{SaltString, rand_core::OsRng},
};
use color_eyre::eyre::bail;
use iroh::{endpoint::Connection, protocol::ProtocolHandler};
use std::{collections::HashMap, net::SocketAddr, sync::Arc};
use tokio::{
    io,
    net::{TcpStream, UdpSocket},
    select,
    sync::mpsc,
    task,
};
use tokio_util::sync::CancellationToken;

async fn auth(
    route: &ForwardRoute,
    hash: Option<&PasswordHash<'_>>,
    conn: &Connection,
) -> color_eyre::Result<()> {
    let mut tx = conn.open_uni().await?;

    if let Some(hash) = hash {
        tx.write_all(AUTH_HEADER).await?;

        let mut rx = conn.accept_uni().await?;

        let mut password_length_bytes = [0u8; 4];
        rx.read_exact(&mut password_length_bytes).await?;
        let password_length = u32::from_le_bytes(password_length_bytes) as usize;
        if password_length > route.auth.as_ref().map(|p| p.len()).unwrap_or(0) {
            bail!("Invalid auth");
        }
        let mut password = vec![0u8; password_length];
        rx.read_exact(&mut password).await?;

        Argon2::default().verify_password(&password, hash)?;
    } else {
        tx.write_all(PUBL_HEADER).await?;
    }

    tx.finish()?;

    Ok(())
}

#[derive(Debug, Clone)]
pub struct ForwardTCP {
    route: Arc<ForwardRoute>,
    hash: Option<Arc<PasswordHash<'static>>>,
    cancel: CancellationToken,
}

impl ForwardTCP {
    pub fn new(route: ForwardRoute, cancel: CancellationToken) -> color_eyre::Result<Self> {
        let route = Arc::new(route);

        let hash = match route.auth.as_ref() {
            Some(pw) => Some(Arc::new(PasswordHash::new(Box::leak(
                Argon2::default()
                    .hash_password(pw.as_bytes(), &SaltString::generate(&mut OsRng))?
                    .to_string()
                    .into_boxed_str(),
            ))?)),
            None => None,
        };

        Ok(Self {
            route,
            hash,
            cancel,
        })
    }

    async fn task(self, conn: Connection) -> color_eyre::Result<()> {
        auth(&self.route, self.hash.as_deref(), &conn).await?;

        let (mut tx, rx) = conn.open_bi().await?;
        tx.write_all(HANDSHAKE).await?;

        let mut socket = TcpStream::connect(self.route.address).await?;
        let mut stream = Stream { send: tx, recv: rx };

        io::copy_bidirectional(&mut socket, &mut stream).await?;

        Ok(())
    }
}

impl ProtocolHandler for ForwardTCP {
    async fn accept(&self, connection: Connection) -> Result<(), iroh::protocol::AcceptError> {
        let ct = self.cancel.clone();

        let forward = Self {
            route: self.route.clone(),
            hash: self.hash.clone(),
            cancel: ct.child_token(),
        };

        task::spawn(async move {
            select! {
                _ = ct.cancelled() => {},
                res = Self::task(forward, connection) => if let Err(e) = res {
                    tracing::warn!("Failed to forward TCP: {}", e);
                }
            }
        });

        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct ForwardUDP {
    route: Arc<ForwardRoute>,
    hash: Option<Arc<PasswordHash<'static>>>,
    cancel: CancellationToken,
}

impl ForwardUDP {
    pub fn new(route: ForwardRoute, cancel: CancellationToken) -> color_eyre::Result<Self> {
        let route = Arc::new(route);

        let hash = match route.auth.as_ref() {
            Some(pw) => Some(Arc::new(PasswordHash::new(Box::leak(
                Argon2::default()
                    .hash_password(pw.as_bytes(), &SaltString::generate(&mut OsRng))?
                    .to_string()
                    .into_boxed_str(),
            ))?)),
            None => None,
        };

        Ok(Self {
            route,
            hash,
            cancel,
        })
    }

    async fn sub_task(
        id: u64,
        addr: SocketAddr,
        tx: mpsc::Sender<(u64, Vec<u8>)>,
        mut rx: mpsc::Receiver<Vec<u8>>,
    ) -> color_eyre::Result<()> {
        let socket =
            UdpSocket::bind("127.0.0.1:0".parse::<SocketAddr>().expect("Valid address")).await?;
        socket.connect(addr).await?;

        let mut buf = [0u8; BUFFER_SIZE];

        loop {
            select! {
                n_res = socket.recv(&mut buf) => {
                    let n = n_res?;
                    tx.send((id, buf[..n].to_vec())).await?;
                }
                packet_opt = rx.recv() => {
                    match packet_opt {
                        Some(packet) => {
                            socket.send(&packet).await?;
                        },
                        None => break,
                    }
                }
            }
        }

        Ok(())
    }

    async fn task(self, conn: Connection) -> color_eyre::Result<()> {
        auth(&self.route, self.hash.as_deref(), &conn).await?;

        let (mut stream_tx, mut stream_rx) = conn.open_bi().await?;
        stream_tx.write_all(HANDSHAKE).await?;

        let mut sockets = HashMap::<u64, mpsc::Sender<Vec<u8>>>::new();

        let (packet_tx, mut packet_rx) = mpsc::channel::<(u64, Vec<u8>)>(100);

        let mut id_bytes = [0u8; 8];
        let mut buf = [0u8; BUFFER_SIZE];

        loop {
            select! {
                packet_res = packet_rx.recv() => {
                    match packet_res {
                        Some((id, packet)) => {
                            stream_tx.write_all(&id.to_le_bytes()).await?;
                            stream_tx.write_all(&(packet.len() as u32).to_le_bytes()).await?;
                            stream_tx.write_all(&packet).await?;
                        },
                        None => break,
                    }
                },
                id_res = stream_rx.read_exact(&mut id_bytes) => {
                    id_res?;
                    let id = u64::from_le_bytes(id_bytes);

                    let mut length_bytes = [0u8; 4];
                    stream_rx.read_exact(&mut length_bytes).await?;
                    let length = u32::from_le_bytes(length_bytes) as usize;
                    if length > BUFFER_SIZE {
                        bail!("Read too big");
                    }
                    stream_rx.read_exact(&mut buf[..length]).await?;

                    let tx = match sockets.get(&id) {
                        Some(t) => t.clone(),
                        None => {
                            let (t, rx) = mpsc::channel(100);

                            sockets.insert(id, t.clone());

                            let ct = self.cancel.child_token();
                            let t2 = packet_tx.clone();
                            let a = self.route.address;
                            task::spawn(async move {
                                select! {
                                    _ = ct.cancelled() => {},
                                    res = Self::sub_task(id, a, t2, rx) => if let Err(e) = res {
                                        tracing::warn!("Failed to forward socket: {}", e);
                                    }
                                }
                            });

                            t
                        }
                    };

                    tx.send(buf[..length].to_vec()).await?;
                }
            }
        }

        Ok(())
    }
}

impl ProtocolHandler for ForwardUDP {
    async fn accept(&self, connection: Connection) -> Result<(), iroh::protocol::AcceptError> {
        let ct = self.cancel.clone();

        let forward = Self {
            route: self.route.clone(),
            hash: self.hash.clone(),
            cancel: ct.child_token(),
        };

        task::spawn(async move {
            select! {
                _ = ct.cancelled() => {},
                res = Self::task(forward, connection) => if let Err(e) = res {
                    tracing::warn!("Failed to forward TCP: {}", e);
                }
            }
        });

        Ok(())
    }
}

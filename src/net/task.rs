use crate::{
    config::{Config, ForwardRoute},
    net::ALPN,
};
use argon2::{
    Argon2, PasswordHash, PasswordHasher, PasswordVerifier,
    password_hash::{SaltString, rand_core::OsRng},
};
use color_eyre::eyre::ContextCompat;
use iroh::{
    Endpoint,
    address_lookup::MdnsAddressLookup,
    endpoint::{Connection, VarInt, presets},
};
use std::collections::HashMap;
use tokio::{select, sync::mpsc, task};
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
        for route in routes {}
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
            if tx.write_all(b"AUTH").await.is_err() {
                continue;
            }

            if let Err(e) = authenticate(&conn, hash).await {
                tracing::warn!("Auth error: {}", e);
                continue;
            }
        } else {
            if tx.write_all(b"PUBL").await.is_err() {
                continue;
            }
        }

        if tx.finish().is_err() {
            continue;
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
    Ok(())
}

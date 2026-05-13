use crate::{
    config::Config,
    net::{ForwardTCP, ForwardUDP, TCP_PROTOCOL, UDP_PROTOCOL, build_alpn, connect},
};
use color_eyre::eyre::ContextCompat;
use iroh::{
    Endpoint, RelayMode, address_lookup::MdnsAddressLookup, endpoint::presets, protocol::Router,
};
use tokio::{select, task};
use tokio_util::sync::CancellationToken;

pub async fn task(config: Config, cancel: CancellationToken) -> color_eyre::Result<()> {
    let key = config.key().context("Invalid identity")?;

    let mut endpoint_builder = if config.local_only.unwrap_or(false) {
        Endpoint::builder(presets::Empty)
    } else {
        Endpoint::builder(presets::N0)
    };
    endpoint_builder = endpoint_builder
        .address_lookup(MdnsAddressLookup::builder().build(key.public())?)
        .secret_key(key)
        .relay_mode(match config.relay {
            Some(url) => RelayMode::Custom(url.into()),
            None => RelayMode::Default,
        });
    if let Some(addr) = config.address {
        endpoint_builder = endpoint_builder.bind_addr(addr)?;
    }
    let endpoint = endpoint_builder.bind().await?;

    if let Some(routes) = config.connect {
        for route in routes {
            let e = endpoint.clone();
            let ct = cancel.child_token();
            let ct2 = ct.child_token();
            task::spawn(async move {
                select! {
                    _ = ct.cancelled() => {},
                    res = connect(e, route, ct2) => if let Err(e) = res {
                        tracing::warn!("Failed to connect: {}", e);
                    }
                }
            });
        }
    }

    let mut router_builder = Router::builder(endpoint);

    if let Some(routes) = config.forward {
        for route in routes {
            let id = route.id.clone();

            let tcp = route.tcp.unwrap_or(true);
            let udp = route.udp.unwrap_or(true);

            if tcp {
                let alpn = build_alpn(TCP_PROTOCOL, &id)?;
                let forward = ForwardTCP::new(route.clone(), cancel.child_token())?;

                router_builder = router_builder.accept(alpn, forward);
            }

            if udp {
                let alpn = build_alpn(UDP_PROTOCOL, &id)?;
                let forward = ForwardUDP::new(route, cancel.child_token())?;

                router_builder = router_builder.accept(alpn, forward);
            }
        }
    }

    let router = router_builder.spawn();

    cancel.cancelled().await;

    router.shutdown().await?;

    Ok(())
}

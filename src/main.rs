mod cli;
mod config;
mod util;

use clap::Parser;
use cli::{Cli, Command, RouteCommand};
use color_eyre::eyre::ContextCompat;
use config::{Config, ConnectRoute, ForwardRoute};
use std::{collections::HashSet, path::PathBuf};
use tokio::fs;
use tracing_subscriber::{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main]
async fn main() -> color_eyre::Result<()> {
    color_eyre::install()?;

    let cli = Cli::parse();

    if let Err(e) = tracing_subscriber::registry()
        .with(EnvFilter::new(&cli.logging))
        .with(tracing_subscriber::fmt::layer())
        .try_init()
    {
        eprintln!("Failed to initialize logger: {}", e);
    }

    let mut config = Config::load(cli.config.as_ref()).await?;

    match cli.command {
        Command::Daemon => {}
        Command::Route { command } => match command {
            RouteCommand::Add { ticket } => {
                let r = match config.connect.take() {
                    Some(mut routes) => {
                        routes.insert(ticket);
                        routes
                    }
                    None => {
                        let mut routes = HashSet::new();
                        routes.insert(ticket);
                        routes
                    }
                };

                config.connect = Some(r);

                config.save(cli.config.as_ref()).await?
            }
            RouteCommand::Create {
                address,
                no_tcp,
                no_udp,
                auth,
                copy,
            } => {
                let forward = ForwardRoute {
                    address,
                    tcp: if no_tcp { Some(false) } else { None },
                    udp: if no_udp { Some(false) } else { None },
                    auth: auth.clone(),
                };

                let connect = ConnectRoute {
                    id: config.key().context("Invalid identity")?.public(),
                    address: "127.0.0.1:0".parse().expect("Valid address"),
                    auth,
                };

                let r = match config.forward.take() {
                    Some(mut routes) => {
                        routes.insert(forward);
                        routes
                    }
                    None => {
                        let mut routes = HashSet::new();
                        routes.insert(forward);
                        routes
                    }
                };

                config.forward = Some(r);

                config.save(cli.config.as_ref()).await?;

                util::display_and_copy(
                    format!(
                        "Run the following to add route:\n\t\"ihnet2 route add {}\"",
                        connect.ticket()
                    ),
                    copy,
                );
            }
            RouteCommand::Import { path } => {
                let data = fs::read(path).await?;
                let route = ConnectRoute::decode(data)?;

                let r = match config.connect.take() {
                    Some(mut routes) => {
                        routes.insert(route);
                        routes
                    }
                    None => {
                        let mut routes = HashSet::new();
                        routes.insert(route);
                        routes
                    }
                };

                config.connect = Some(r);

                config.save(cli.config.as_ref()).await?
            }
            RouteCommand::Export {
                address,
                no_tcp,
                no_udp,
                auth,
                to,
            } => {
                let forward = ForwardRoute {
                    address,
                    tcp: if no_tcp { Some(false) } else { None },
                    udp: if no_udp { Some(false) } else { None },
                    auth: auth.clone(),
                };

                let connect = ConnectRoute {
                    id: config.key().context("Invalid identity")?.public(),
                    address: "127.0.0.1:0".parse().expect("Valid address"),
                    auth,
                };

                let r = match config.forward.take() {
                    Some(mut routes) => {
                        routes.insert(forward);
                        routes
                    }
                    None => {
                        let mut routes = HashSet::new();
                        routes.insert(forward);
                        routes
                    }
                };

                config.forward = Some(r);

                config.save(cli.config.as_ref()).await?;

                let path = to.unwrap_or_else(|| PathBuf::from("route.json"));
                let data = connect.encode()?;

                fs::write(path, data).await?;
            }
        },
    }

    Ok(())
}

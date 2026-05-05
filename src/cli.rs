use crate::config::ConnectRoute;
use clap::{Parser, Subcommand};
use iroh::RelayUrl;
use std::{net::SocketAddr, path::PathBuf};

#[derive(Parser)]
#[command(name = env!("CARGO_PKG_NAME"))]
#[command(version = env!("CARGO_PKG_VERSION"))]
#[command(about = env!("CARGO_PKG_DESCRIPTION"))]
#[command(author = env!("CARGO_PKG_AUTHORS"))]
pub struct Cli {
    /// Sets custom log level for application
    #[arg(long, short = 'l', env = "RUST_LOG", default_value_t = String::from("ihnet2=info"))]
    pub logging: String,

    /// Custom relay url
    #[arg(long, short, env = "IHNET2_RELAY")]
    pub relay: Option<RelayUrl>,

    /// Custom listen address
    #[arg(long, short, env = "IHNET2_ADDRESS")]
    pub address: Option<SocketAddr>,

    /// Custom config directory
    #[arg(long, short = 'c', env = "IHNET2_CONFIG")]
    pub config: Option<PathBuf>,

    #[clap(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
    /// Launch IHNET2 daemon
    Daemon,
    /// Configure connections
    Route {
        #[clap(subcommand)]
        command: RouteCommand,
    },
}

#[derive(Subcommand)]
pub enum RouteCommand {
    /// Add a route
    Add {
        /// Encoded route
        ticket: ConnectRoute,

        /// Address to listen on
        #[arg(long, short)]
        address: Option<SocketAddr>,

        /// Path name
        #[arg(long, short)]
        name: Option<String>,
    },
    /// Create a route
    Create {
        /// Local address to share
        address: SocketAddr,

        /// Don't share TCP
        #[arg(long, short = 't')]
        no_tcp: bool,

        /// Don't share UDP
        #[arg(long, short = 'u')]
        no_udp: bool,

        /// Authentication
        #[arg(long, short)]
        auth: Option<String>,

        /// Copy command to clipboard
        #[arg(long, short)]
        copy: bool,
    },
    /// Import a route
    Import {
        /// Path to route file
        path: PathBuf,

        /// Address to listen on
        #[arg(long, short)]
        address: Option<SocketAddr>,

        /// Path name
        #[arg(long, short)]
        name: Option<String>,
    },
    /// Export a route
    Export {
        /// Local address to share
        address: SocketAddr,

        /// Don't share TCP
        #[arg(long, short = 't')]
        no_tcp: bool,

        /// Don't share UDP
        #[arg(long, short = 'u')]
        no_udp: bool,

        /// Authentication
        #[arg(long, short)]
        auth: Option<String>,

        /// Output route path
        to: Option<PathBuf>,
    },
}

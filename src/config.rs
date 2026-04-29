use base64::{Engine, prelude::BASE64_STANDARD};
use iroh::{PublicKey, SecretKey};
use serde::{Deserialize, Serialize};
use std::{collections::HashSet, env, net::SocketAddr, path::Path, str::FromStr};
use tokio::{fs, io};

#[derive(Serialize, Deserialize, PartialEq, Eq, Hash, Clone)]
pub struct ForwardRoute {
    pub id: String,
    pub address: SocketAddr,
    pub tcp: Option<bool>,
    pub udp: Option<bool>,
    pub auth: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Hash)]
pub struct ConnectRoute {
    pub id: String,
    pub public_key: PublicKey,
    pub tcp: Option<bool>,
    pub udp: Option<bool>,
    pub address: Option<SocketAddr>,
    pub auth: Option<String>,
}

impl ConnectRoute {
    pub fn encode(&self) -> serde_json::Result<Vec<u8>> {
        serde_json::to_vec_pretty(self)
    }

    pub fn decode<D: AsRef<[u8]>>(d: D) -> serde_json::Result<Self> {
        serde_json::from_slice(d.as_ref())
    }

    pub fn ticket(&self) -> String {
        BASE64_STANDARD.encode(postcard::to_stdvec(self).expect("Failed to encode ticket"))
    }

    pub fn from_ticket<S: AsRef<str>>(data: S) -> Option<Self> {
        postcard::from_bytes(&BASE64_STANDARD.decode(data.as_ref()).ok()?).ok()
    }
}

impl FromStr for ConnectRoute {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_ticket(s).ok_or("Invalid ticket")
    }
}

#[derive(Serialize, Deserialize)]
pub struct Config {
    identity: String,
    pub local_only: Option<bool>,
    pub forward: Option<HashSet<ForwardRoute>>,
    pub connect: Option<HashSet<ConnectRoute>>,
}

impl Config {
    pub fn new() -> Self {
        let key = SecretKey::generate();
        let identity = BASE64_STANDARD.encode(key.to_bytes());

        Self {
            identity,
            local_only: None,
            forward: None,
            connect: None,
        }
    }

    pub fn key(&self) -> Option<SecretKey> {
        let decoded = BASE64_STANDARD.decode(&self.identity).ok()?;

        if decoded.len() != 32 {
            return None;
        }

        let mut key_bytes = [0u8; 32];
        key_bytes.clone_from_slice(&decoded);

        Some(SecretKey::from_bytes(&key_bytes))
    }

    pub async fn load<P: AsRef<Path>>(p: Option<P>) -> io::Result<Self> {
        let path = match p {
            Some(v) => v.as_ref().to_path_buf(),
            None => env::home_dir()
                .ok_or_else(|| io::Error::other("Failed to get home directory"))?
                .join(".ihnet2")
                .join("config.json"),
        };

        let cfg = if path.exists() {
            let data = fs::read(path).await?;

            serde_json::from_slice(&data).map_err(io::Error::other)?
        } else {
            if let Some(parent) = path.parent()
                && !parent.exists()
            {
                fs::create_dir_all(parent).await?;
            }

            let default = Self::new();

            let data = serde_json::to_vec_pretty(&default).map_err(io::Error::other)?;

            fs::write(path, data).await?;

            default
        };

        Ok(cfg)
    }

    pub async fn save<P: AsRef<Path>>(&self, p: Option<P>) -> io::Result<()> {
        let path = match p {
            Some(v) => v.as_ref().to_path_buf(),
            None => env::home_dir()
                .ok_or_else(|| io::Error::other("Failed to get home directory"))?
                .join(".ihnet2")
                .join("config.json"),
        };

        let data = serde_json::to_vec_pretty(self).map_err(io::Error::other)?;

        fs::write(path, data).await?;

        Ok(())
    }
}

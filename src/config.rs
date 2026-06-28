use base64::{Engine, prelude::BASE64_STANDARD};
use iroh::{PublicKey, RelayUrl, SecretKey};
use serde::{Deserialize, Serialize};
use std::{collections::HashSet, env, net::SocketAddr, path::Path, str::FromStr};
use tokio::{fs, io};

#[derive(Serialize, Deserialize, PartialEq, Eq, Hash, Clone, Debug)]
pub struct ForwardRoute {
    pub id: String,
    pub address: SocketAddr,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tcp: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub udp: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Hash, Debug)]
pub struct ConnectRoute {
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    pub public_key: PublicKey,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tcp: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub udp: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<SocketAddr>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth: Option<String>,
}

impl ConnectRoute {
    pub fn encode(&self) -> yaml_serde::Result<String> {
        yaml_serde::to_string(self)
    }

    pub fn decode<D: AsRef<[u8]>>(d: D) -> yaml_serde::Result<Self> {
        yaml_serde::from_slice(d.as_ref())
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<SocketAddr>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub relay: Option<RelayUrl>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub local_only: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub forward: Option<HashSet<ForwardRoute>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connect: Option<HashSet<ConnectRoute>>,
}

impl Config {
    pub fn new() -> Self {
        let key = SecretKey::generate();
        let identity = BASE64_STANDARD.encode(key.to_bytes());

        Self {
            identity,
            address: None,
            relay: None,
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
                .join(".ihnet2.yaml"),
        };

        let cfg = if path.exists() {
            let data = fs::read(path).await?;

            yaml_serde::from_slice(&data).map_err(io::Error::other)?
        } else {
            if let Some(parent) = path.parent()
                && !parent.exists()
            {
                fs::create_dir_all(parent).await?;
            }

            let default = Self::new();

            let data = yaml_serde::to_string(&default).map_err(io::Error::other)?;

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
                .join(".ihnet2.yaml"),
        };

        let data = yaml_serde::to_string(self).map_err(io::Error::other)?;

        fs::write(path, data).await?;

        Ok(())
    }
}

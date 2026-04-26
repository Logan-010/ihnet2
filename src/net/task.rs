use crate::config::Config;
use tokio_util::sync::CancellationToken;

pub async fn task(config: Config, cancel: CancellationToken) -> color_eyre::Result<()> {
    Ok(())
}

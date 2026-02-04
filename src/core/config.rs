use fred::prelude::{Server, ServerConfig};
use serde::Deserialize;
use std::fs;
use std::path::Path;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ConfigError {
    #[error(transparent)]
    FSError(#[from] std::io::Error),
    #[error(transparent)]
    SerdeError(#[from] toml::de::Error),
}

#[derive(Deserialize, Clone, Default)]
pub struct DB {
    pub database: String,
    pub host: String,
    pub user: String,
    pub password: String,
}

impl DB {
    fn is_valid(&self) -> bool {
        !self.database.is_empty()
            && !self.host.is_empty()
            && !self.password.is_empty()
            && !self.user.is_empty()
    }

    pub fn connection_string(&self) -> String {
        let password: String =
            url::form_urlencoded::byte_serialize(self.password.as_bytes()).collect();

        format!(
            "postgres://{}:{}@{}/{}",
            self.user, password, self.host, self.database
        )
    }
}

#[derive(Deserialize, Clone, Default)]
pub struct OIDCConfig {
    pub url: String,
    pub client_id: String,
    pub client_secret: String,
    pub redirect_url: String,
    pub authorized_callback_urls: Vec<String>,
}

#[derive(Deserialize, Clone, Default)]
pub struct RedisConfig {
    pub connection_string: Option<String>,
    pub sentinel_enabled: Option<bool>,
    pub hostname: Option<String>,
    pub port: Option<u16>,
    pub username: Option<String>,
    pub password: Option<String>,
    pub service_name: Option<String>,
}

impl TryFrom<RedisConfig> for fred::types::config::Config {
    type Error = String;

    fn try_from(value: RedisConfig) -> Result<Self, Self::Error> {
        if value.sentinel_enabled.unwrap_or_default() {
            Ok(Self {
                server: ServerConfig::Sentinel {
                    service_name: value.service_name.unwrap_or_default(),
                    hosts: vec![Server::new(
                        value.hostname.unwrap_or_default().as_str(),
                        value.port.unwrap_or(26379),
                    )],
                },
                username: value.username.unwrap_or_default().into(),
                password: value.password.unwrap_or_default().into(),
                ..Default::default()
            })
        } else {
            let connection_string = value
                .connection_string
                .unwrap_or("redis://127.0.0.1/".to_string());
            match Self::from_url(connection_string.as_str()) {
                Ok(result) => Ok(result),
                Err(err) => Err(err.to_string()),
            }
        }
    }
}

#[derive(Deserialize, Clone, Default)]
pub struct Config {
    pub cors_hosts: Vec<String>,
    pub oidc: OIDCConfig,
    #[serde(default)]
    pub secure_session: bool,
    #[serde(default)]
    pub redis: RedisConfig,
    pub db: DB,
}

impl Config {
    pub fn parse(path: Option<String>) -> Result<Self, ConfigError> {
        let path = path.unwrap_or("config.toml".to_string());
        let path = Path::new(path.as_str());
        let config_text = fs::read_to_string(path)?;

        let config: Config = toml::from_str(config_text.as_str())?;

        Ok(config)
    }

    pub fn is_valid(&self) -> bool {
        self.db.is_valid()
    }
}

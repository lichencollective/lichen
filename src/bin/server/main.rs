use anyhow::anyhow;
use clap::{Parser, Subcommand};
use fred::clients::Pool;
use fred::interfaces::ClientLike;
use fred::prelude::ReconnectPolicy;
use lichen::core::application::{Application, ApplicationServices};
use lichen::core::config::Config;
use lichen::domain::auth;
use lichen::inbound::http::router;
use lichen::outbound::db::connection::Db;
use lichen::outbound::db::repository::Repository;
use lichen::outbound::oidc::adapter::{NewOIDCServiceParams, OIDCAdapter};
use lichen::outbound::session::{SessionAdapter, SessionAdapterFactory};
use sqlx::Postgres;
use sqlx::postgres::PgPoolOptions;
use std::process::exit;
use tower_sessions_redis_store::RedisStore;
use tracing::error;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

type ApplicationAlias = Application<
    auth::Service<SessionAdapter, OIDCAdapter, SessionAdapterFactory>,
    lichen::domain::lichen::Service<Repository>,
>;

#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Cli {
    #[arg(long)]
    config_path: Option<String>,
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    Run,
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
                format!("{}=debug,tower_http=debug", env!("CARGO_CRATE_NAME")).into()
            }),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    if let Err(e) = start(cli).await {
        error!("Error: {:#?}", e);
        exit(1);
    }
}

async fn start(cli: Cli) -> anyhow::Result<(), anyhow::Error> {
    let config = Config::parse(cli.config_path)?;
    if !config.is_valid() {
        return Err(anyhow!("config is not valid"));
    }

    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(config.db.connection_string().as_str())
        .await
        .expect("could not connect to the database");

    sqlx::migrate!("./migrations").run(&pool).await?;

    let application = create_application(pool, config).await?;

    match cli.command {
        None => Ok(()),
        Some(subcommand) => match subcommand {
            Commands::Run => run_server(application).await,
        },
    }
}
async fn create_application(
    pool: sqlx::Pool<Postgres>,
    config: Config,
) -> Result<ApplicationAlias, anyhow::Error> {
    let db = Db::new(pool);

    tracing::debug!("creating oidc service");
    let oidc_service = OIDCAdapter::new(NewOIDCServiceParams {
        issuer_url: config.oidc.url.clone(),
        client_id: config.oidc.client_id.clone(),
        client_secret: config.oidc.client_secret.clone(),
        redirect_url: config.oidc.redirect_url.clone(),
    })
    .await
    .map_err(|e| anyhow!(e.to_string()))?;
    tracing::debug!("created oidc service");

    let repo = Repository::new(db.clone().pool());
    let oidc_service = oidc_service;
    let session_factory = SessionAdapterFactory::new();
    let auth_service = auth::Service::new(oidc_service, session_factory);
    let lichen_service = lichen::domain::lichen::Service::new(repo);

    Ok(Application::new(config, auth_service, lichen_service))
}

async fn run_server(app: ApplicationAlias) -> anyhow::Result<()> {
    tracing::debug!("creating session store.");
    let session_store = new_session_store(app.config())
        .await
        .map_err(|_| anyhow!("failed to create redis session store"))?;
    tracing::debug!("created session store.");

    let router = router(app, session_store);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000")
        .await
        .map_err(|_| anyhow!("server failed to bind"))?;

    tracing::debug!(
        "listening on {}",
        listener
            .local_addr()
            .map_err(|_| anyhow!("failed to get local_addr"))?
    );

    axum::serve(listener, router)
        .await
        .map_err(|_| anyhow!("failed to start server"))
}

async fn new_session_store(config: Config) -> Result<RedisStore<Pool>, anyhow::Error> {
    let config: fred::types::config::Config = config
        .redis
        .try_into()
        .map_err(|_| anyhow!("failed to parse redis session store connection url"))?;

    let pool = Pool::new(
        config,
        None,
        None,
        Some(ReconnectPolicy::new_constant(0, 5_000)),
        10,
    )?;
    let redis_connection = pool.connect();
    tokio::spawn(redis_connection);
    pool.wait_for_connect().await.map_err(|e| {
        error!("Axum server stopped running: {:?}", e);
        anyhow!("Axum server stopped running")
    })?;

    let session_store = RedisStore::new(pool);

    Ok(session_store)
}

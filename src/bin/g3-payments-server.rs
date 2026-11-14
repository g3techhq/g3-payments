//! `g3-payments-server`: Stripe Checkout and license keys for g3 apps that
//! have no server of their own. See `g3_payments::server::standalone` for
//! its settings.
//!
//! ```text
//! g3-payments-server                  serve
//! g3-payments-server migrate start    load the schema, then exit
//! g3-payments-server migrate complete nothing to remove; exits
//! g3-payments-server gen-key          print a new license signing key and its public key
//! ```

use g3_payments::server::{
    license_keys::{LicenseSigner, generate_seed},
    standalone::{Config, Server},
    surreal::SurrealStore,
};
use surrealdb::{Surreal, engine::any::Any, opt::auth::Root};

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();
    let args: Vec<String> = std::env::args().skip(1).collect();
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    let result = match args.as_slice() {
        ["gen-key"] => {
            let seed = generate_seed();
            let signer = LicenseSigner::from_seed(&seed).expect("fresh seed");
            println!("<APP>_LICENSE_SIGNING_KEY={seed}");
            println!("public key for the app: {}", signer.public_key());
            Ok(())
        }
        ["migrate", "start"] => migrate().await,
        ["migrate", "complete"] => Ok(()),
        [] => serve().await,
        _ => Err("usage: g3-payments-server [gen-key | migrate start | migrate complete]".into()),
    };
    if let Err(error) = result {
        tracing::error!(%error, "g3_payments_server_failed");
        std::process::exit(1);
    }
}

fn env(name: &str, default: Option<&str>) -> Result<String, String> {
    std::env::var(name)
        .ok()
        .filter(|value| !value.trim().is_empty())
        .or_else(|| default.map(str::to_string))
        .ok_or_else(|| format!("{name} is not set"))
}

async fn connect() -> Result<Surreal<Any>, String> {
    let host = env("SURREALDB_HOST", Some("ws://127.0.0.1:8000"))?;
    let db = surrealdb::engine::any::connect(host.as_str())
        .await
        .map_err(|error| format!("database: {error}"))?;
    if let (Ok(username), Ok(password)) =
        (env("SURREALDB_USER", None), env("SURREALDB_PASSWORD", None))
    {
        db.signin(Root { username, password })
            .await
            .map_err(|error| format!("database sign-in: {error}"))?;
    }
    db.use_ns(env("SURREALDB_NAMESPACE", Some("g3-payments"))?)
        .use_db(env("SURREALDB_NAME", Some("production"))?)
        .await
        .map_err(|error| format!("database: {error}"))?;
    Ok(db)
}

async fn migrate() -> Result<(), String> {
    let db = connect().await?;
    SurrealStore::apply_schema(&db)
        .await
        .map_err(|error| error.to_string())?;
    tracing::info!("schema_applied");
    Ok(())
}

async fn serve() -> Result<(), String> {
    let config = Config::from_env()?;
    let db = connect().await?;
    SurrealStore::apply_schema(&db)
        .await
        .map_err(|error| error.to_string())?;
    let port = config.port;
    let apps: Vec<String> = config.apps.iter().map(|app| app.id.clone()).collect();
    let router = Server::new(&config, db)?.router();
    let listener = tokio::net::TcpListener::bind(("0.0.0.0", port))
        .await
        .map_err(|error| format!("listen on {port}: {error}"))?;
    tracing::info!(port, ?apps, "g3_payments_server_listening");
    axum::serve(listener, router)
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await
        .map_err(|error| error.to_string())
}

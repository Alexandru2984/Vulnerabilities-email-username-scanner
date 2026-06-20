use anyhow::Context;
use sqlx::PgPool;
use sqlx::postgres::PgPoolOptions;
use std::env;
use std::time::Duration;

const DEFAULT_DB_MAX_CONNECTIONS: u32 = 10;
const DEFAULT_DB_MIN_CONNECTIONS: u32 = 2;
const DEFAULT_DB_ACQUIRE_TIMEOUT_SECS: u64 = 5;
const DEFAULT_DB_IDLE_TIMEOUT_SECS: u64 = 300;

const MAX_ALLOWED_DB_CONNECTIONS: u32 = 64;
const MAX_ALLOWED_DB_ACQUIRE_TIMEOUT_SECS: u64 = 60;
const MAX_ALLOWED_DB_IDLE_TIMEOUT_SECS: u64 = 3_600;

#[derive(Debug, Clone, Copy)]
struct DbPoolConfig {
    max_connections: u32,
    min_connections: u32,
    acquire_timeout_secs: u64,
    idle_timeout_secs: u64,
}

pub async fn init_db() -> anyhow::Result<PgPool> {
    let database_url =
        env::var("DATABASE_URL").context("DATABASE_URL must be set before starting the server.")?;
    let config = configured_db_pool()?;

    let pool = PgPoolOptions::new()
        .max_connections(config.max_connections)
        .min_connections(config.min_connections)
        .acquire_timeout(Duration::from_secs(config.acquire_timeout_secs))
        .idle_timeout(Duration::from_secs(config.idle_timeout_secs))
        .connect(&database_url)
        .await?;

    // Run migrations
    sqlx::migrate!("./migrations").run(&pool).await?;

    Ok(pool)
}

fn configured_db_pool() -> anyhow::Result<DbPoolConfig> {
    let max_connections = parse_env_u32(
        "DB_MAX_CONNECTIONS",
        DEFAULT_DB_MAX_CONNECTIONS,
        1,
        MAX_ALLOWED_DB_CONNECTIONS,
    )?;
    let min_connections = parse_env_u32(
        "DB_MIN_CONNECTIONS",
        DEFAULT_DB_MIN_CONNECTIONS,
        0,
        MAX_ALLOWED_DB_CONNECTIONS,
    )?;

    if min_connections > max_connections {
        anyhow::bail!("DB_MIN_CONNECTIONS cannot be greater than DB_MAX_CONNECTIONS.");
    }

    Ok(DbPoolConfig {
        max_connections,
        min_connections,
        acquire_timeout_secs: parse_env_u64(
            "DB_ACQUIRE_TIMEOUT_SECS",
            DEFAULT_DB_ACQUIRE_TIMEOUT_SECS,
            1,
            MAX_ALLOWED_DB_ACQUIRE_TIMEOUT_SECS,
        )?,
        idle_timeout_secs: parse_env_u64(
            "DB_IDLE_TIMEOUT_SECS",
            DEFAULT_DB_IDLE_TIMEOUT_SECS,
            30,
            MAX_ALLOWED_DB_IDLE_TIMEOUT_SECS,
        )?,
    })
}

fn parse_env_u32(name: &str, default: u32, min: u32, max: u32) -> anyhow::Result<u32> {
    match env::var(name) {
        Ok(value) => parse_bounded_u32(name, &value, min, max),
        Err(env::VarError::NotPresent) => Ok(default),
        Err(env::VarError::NotUnicode(_)) => anyhow::bail!("{name} must be valid UTF-8."),
    }
}

fn parse_env_u64(name: &str, default: u64, min: u64, max: u64) -> anyhow::Result<u64> {
    match env::var(name) {
        Ok(value) => parse_bounded_u64(name, &value, min, max),
        Err(env::VarError::NotPresent) => Ok(default),
        Err(env::VarError::NotUnicode(_)) => anyhow::bail!("{name} must be valid UTF-8."),
    }
}

fn parse_bounded_u32(name: &str, value: &str, min: u32, max: u32) -> anyhow::Result<u32> {
    let parsed = value
        .trim()
        .parse::<u32>()
        .map_err(|_| anyhow::anyhow!("{name} must be an integer between {min} and {max}."))?;

    if !(min..=max).contains(&parsed) {
        anyhow::bail!("{name} must be between {min} and {max}.");
    }

    Ok(parsed)
}

fn parse_bounded_u64(name: &str, value: &str, min: u64, max: u64) -> anyhow::Result<u64> {
    let parsed = value
        .trim()
        .parse::<u64>()
        .map_err(|_| anyhow::anyhow!("{name} must be an integer between {min} and {max}."))?;

    if !(min..=max).contains(&parsed) {
        anyhow::bail!("{name} must be between {min} and {max}.");
    }

    Ok(parsed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounded_u32_parser_accepts_only_configured_range() {
        assert_eq!(parse_bounded_u32("TEST", "1", 1, 64).unwrap(), 1);
        assert_eq!(parse_bounded_u32("TEST", " 64 ", 1, 64).unwrap(), 64);
        assert!(parse_bounded_u32("TEST", "0", 1, 64).is_err());
        assert!(parse_bounded_u32("TEST", "65", 1, 64).is_err());
        assert!(parse_bounded_u32("TEST", "abc", 1, 64).is_err());
    }

    #[test]
    fn bounded_u64_parser_accepts_only_configured_range() {
        assert_eq!(parse_bounded_u64("TEST", "30", 30, 3600).unwrap(), 30);
        assert_eq!(parse_bounded_u64("TEST", " 3600 ", 30, 3600).unwrap(), 3600);
        assert!(parse_bounded_u64("TEST", "29", 30, 3600).is_err());
        assert!(parse_bounded_u64("TEST", "3601", 30, 3600).is_err());
        assert!(parse_bounded_u64("TEST", "abc", 30, 3600).is_err());
    }
}

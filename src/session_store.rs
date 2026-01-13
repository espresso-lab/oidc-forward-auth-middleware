use redis::aio::ConnectionManager;
use redis::AsyncCommands;
use serde::{Deserialize, Serialize};
use std::sync::OnceLock;
use std::time::Duration;
use tracing::{error, info};
use uuid::Uuid;

static REDIS_CONNECTION: OnceLock<Option<ConnectionManager>> = OnceLock::new();
static SESSION_TTL: Duration = Duration::from_secs(24 * 60 * 60); // 24 hours
static LOCK_TTL: Duration = Duration::from_secs(10); // 10 seconds for refresh lock

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub access_token: String,
    pub refresh_token: String,
    pub hostname: String,
}

pub async fn init_redis(redis_url: Option<String>) {
    if let Some(url) = redis_url {
        match redis::Client::open(url.as_str()) {
            Ok(client) => match ConnectionManager::new(client).await {
                Ok(conn) => {
                    info!("Connected to Redis/Valkey session store");
                    REDIS_CONNECTION.get_or_init(|| Some(conn));
                }
                Err(e) => {
                    error!("Failed to create Redis connection manager: {}", e);
                    REDIS_CONNECTION.get_or_init(|| None);
                }
            },
            Err(e) => {
                error!("Failed to open Redis client: {}", e);
                REDIS_CONNECTION.get_or_init(|| None);
            }
        }
    } else {
        info!("Session store disabled (no REDIS_URL configured)");
        REDIS_CONNECTION.get_or_init(|| None);
    }
}

pub fn is_enabled() -> bool {
    REDIS_CONNECTION.get().is_some_and(Option::is_some)
}

fn get_connection() -> Option<ConnectionManager> {
    REDIS_CONNECTION.get()?.clone()
}

fn session_key(session_id: &str) -> String {
    format!("session:{session_id}")
}

fn lock_key(session_id: &str) -> String {
    format!("lock:{session_id}")
}

pub fn generate_session_id() -> String {
    Uuid::new_v4().to_string()
}

pub async fn create_session(session: &Session) -> Option<String> {
    let mut conn = get_connection()?;
    let session_id = generate_session_id();
    let key = session_key(&session_id);

    let json = match serde_json::to_string(session) {
        Ok(j) => j,
        Err(e) => {
            error!("Failed to serialize session: {}", e);
            return None;
        }
    };

    match conn
        .set_ex::<_, _, ()>(&key, &json, SESSION_TTL.as_secs())
        .await
    {
        Ok(()) => Some(session_id),
        Err(e) => {
            error!("Failed to create session: {}", e);
            None
        }
    }
}

pub async fn get_session(session_id: &str) -> Option<Session> {
    let mut conn = get_connection()?;
    let key = session_key(session_id);

    let json: String = match conn.get(&key).await {
        Ok(j) => j,
        Err(_) => return None,
    };

    match serde_json::from_str(&json) {
        Ok(s) => Some(s),
        Err(e) => {
            error!("Failed to deserialize session: {}", e);
            None
        }
    }
}

pub async fn update_session(session_id: &str, session: &Session) -> bool {
    let Some(mut conn) = get_connection() else {
        return false;
    };
    let key = session_key(session_id);

    let json = match serde_json::to_string(session) {
        Ok(j) => j,
        Err(e) => {
            error!("Failed to serialize session: {}", e);
            return false;
        }
    };

    match conn
        .set_ex::<_, _, ()>(&key, &json, SESSION_TTL.as_secs())
        .await
    {
        Ok(()) => true,
        Err(e) => {
            error!("Failed to update session: {e}");
            false
        }
    }
}

pub async fn delete_session(session_id: &str) -> bool {
    let Some(mut conn) = get_connection() else {
        return false;
    };
    let key = session_key(session_id);

    match conn.del::<_, ()>(&key).await {
        Ok(()) => true,
        Err(e) => {
            error!("Failed to delete session: {e}");
            false
        }
    }
}

pub async fn acquire_refresh_lock(session_id: &str) -> bool {
    let Some(mut conn) = get_connection() else {
        return false;
    };
    let key = lock_key(session_id);

    let result: redis::RedisResult<bool> = redis::cmd("SET")
        .arg(&key)
        .arg("1")
        .arg("NX")
        .arg("EX")
        .arg(LOCK_TTL.as_secs())
        .query_async(&mut conn)
        .await;

    result.unwrap_or_default()
}

pub async fn release_refresh_lock(session_id: &str) {
    if let Some(mut conn) = get_connection() {
        let key = lock_key(session_id);
        let _: redis::RedisResult<()> = conn.del(&key).await;
    }
}

pub async fn wait_for_refresh(session_id: &str) -> Option<Session> {
    for _ in 0..20 {
        tokio::time::sleep(Duration::from_millis(100)).await;

        let mut conn = get_connection()?;
        let key = lock_key(session_id);
        let exists: bool = conn.exists(&key).await.unwrap_or(true);

        if !exists {
            return get_session(session_id).await;
        }
    }
    None
}

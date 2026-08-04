use camellia_remote_protocol::{log, ResultType};
use sqlx::{
    sqlite::{SqliteConnectOptions, SqliteJournalMode, SqliteSynchronous},
    ConnectOptions, Connection, Error as SqlxError, Row, SqliteConnection,
};
use std::{ops::DerefMut, str::FromStr, time::Duration};

type Pool = deadpool::managed::Pool<DbPool>;

pub struct DbPool {
    url: String,
}

impl deadpool::managed::Manager for DbPool {
    type Type = SqliteConnection;
    type Error = SqlxError;
    async fn create(&self) -> Result<SqliteConnection, SqlxError> {
        let opt = SqliteConnectOptions::from_str(&self.url)?
            .create_if_missing(true)
            .foreign_keys(true)
            .journal_mode(SqliteJournalMode::Wal)
            .synchronous(SqliteSynchronous::Full)
            .busy_timeout(Duration::from_secs(10))
            .log_statements(log::LevelFilter::Debug);
        SqliteConnection::connect_with(&opt).await
    }
    async fn recycle(
        &self,
        obj: &mut SqliteConnection,
        _metrics: &deadpool::managed::Metrics,
    ) -> deadpool::managed::RecycleResult<SqlxError> {
        Ok(obj.ping().await?)
    }
}

#[derive(Clone)]
pub struct Database {
    pool: Pool,
}

#[derive(Default)]
pub struct Peer {
    pub guid: Vec<u8>,
    pub uuid: Vec<u8>,
    pub pk: Vec<u8>,
    pub info: String,
}

impl Database {
    pub async fn new(url: &str) -> ResultType<Database> {
        let n = crate::common::get_bounded_usize_arg("MAX_DATABASE_CONNECTIONS", 1, 1, 32)?;
        log::debug!("MAX_DATABASE_CONNECTIONS={}", n);
        let pool = Pool::builder(DbPool {
            url: url.to_owned(),
        })
        .max_size(n)
        .build()?;
        let _ = pool.get().await?; // test
        let db = Database { pool };
        db.create_tables().await?;
        Ok(db)
    }

    async fn create_tables(&self) -> ResultType<()> {
        sqlx::query(
            "
            create table if not exists peer (
                guid blob primary key not null,
                id varchar(100) not null,
                uuid blob not null,
                pk blob not null,
                created_at datetime not null default(current_timestamp),
                user blob,
                status tinyint,
                note varchar(300),
                info text not null
            ) without rowid;
            create unique index if not exists index_peer_id on peer (id);
            create index if not exists index_peer_user on peer (user);
            create index if not exists index_peer_created_at on peer (created_at);
            create index if not exists index_peer_status on peer (status);
        ",
        )
        .execute(self.pool.get().await?.deref_mut())
        .await?;
        Ok(())
    }

    pub async fn get_peer(&self, id: &str) -> ResultType<Option<Peer>> {
        let row = sqlx::query("select guid, uuid, pk, info from peer where id = ?")
            .bind(id)
            .fetch_optional(self.pool.get().await?.deref_mut())
            .await?;
        match row {
            Some(row) => Ok(Some(Peer {
                guid: row.try_get("guid")?,
                uuid: row.try_get("uuid")?,
                pk: row.try_get("pk")?,
                info: row.try_get("info")?,
            })),
            None => Ok(None),
        }
    }

    pub async fn insert_peer(
        &self,
        id: &str,
        uuid: &[u8],
        pk: &[u8],
        info: &str,
    ) -> ResultType<Vec<u8>> {
        let guid = uuid::Uuid::new_v4().as_bytes().to_vec();
        sqlx::query("insert into peer(guid, id, uuid, pk, info) values(?, ?, ?, ?, ?)")
            .bind(guid.as_slice())
            .bind(id)
            .bind(uuid)
            .bind(pk)
            .bind(info)
            .execute(self.pool.get().await?.deref_mut())
            .await?;
        Ok(guid)
    }

    pub async fn update_identity(
        &self,
        guid: &[u8],
        id: &str,
        uuid: &[u8],
        pk: &[u8],
        info: &str,
    ) -> ResultType<()> {
        sqlx::query("update peer set id=?, uuid=?, pk=?, info=? where guid=?")
            .bind(id)
            .bind(uuid)
            .bind(pk)
            .bind(info)
            .bind(guid)
            .execute(self.pool.get().await?.deref_mut())
            .await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use camellia_remote_protocol::tokio;
    use sqlx::Connection;
    use std::{
        fs,
        path::{Path, PathBuf},
    };

    struct TestDatabaseDirectory {
        directory: PathBuf,
        path: PathBuf,
    }

    impl TestDatabaseDirectory {
        fn new() -> Self {
            let directory = std::env::temp_dir().join(format!(
                "camellia-server-database-{}-{}",
                std::process::id(),
                uuid::Uuid::new_v4()
            ));
            fs::create_dir(&directory).unwrap();
            Self {
                directory: directory.clone(),
                path: directory.join("database.sqlite3"),
            }
        }

        fn path(&self) -> &Path {
            &self.path
        }

        fn directory(&self) -> &Path {
            &self.directory
        }
    }

    impl Drop for TestDatabaseDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.directory);
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn concurrent_insert_and_read() {
        let directory = TestDatabaseDirectory::new();
        let path = directory.path().to_owned();
        let path_string = path.to_string_lossy().into_owned();
        let db = super::Database::new(&path_string).await.unwrap();
        let mut jobs = vec![];
        for i in 0..256 {
            let cloned = db.clone();
            let id = i.to_string();
            jobs.push(tokio::spawn(async move {
                let empty_vec = Vec::new();
                cloned.insert_peer(&id, &empty_vec, &empty_vec, "").await
            }));
        }
        for job in jobs {
            job.await.unwrap().unwrap();
        }

        let mut jobs = vec![];
        for i in 0..256 {
            let cloned = db.clone();
            let id = i.to_string();
            jobs.push(tokio::spawn(async move { cloned.get_peer(&id).await }));
        }
        for job in jobs {
            assert!(job.await.unwrap().unwrap().is_some());
        }

        // Dropping a SqliteConnection only signals its worker thread. Windows
        // keeps the database files locked until that worker has exited, so
        // drain the idle pool and await each connection's graceful shutdown
        // before checking temporary-directory cleanup.
        let connections = db.pool.retain(|_, _| false).removed;
        db.pool.close();
        drop(db);
        for connection in connections {
            connection.close().await.unwrap();
        }
        let temporary_directory = directory.directory().to_owned();
        drop(directory);
        assert!(!temporary_directory.exists());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn deployment_generation_survives_database_restart() {
        let directory = TestDatabaseDirectory::new();
        let path_string = directory.path().to_string_lossy().into_owned();
        let info = serde_json::to_string(&crate::peer::PeerInfo {
            ip: "192.0.2.10".to_owned(),
            deployment_generation: 7,
        })
        .unwrap();

        let first = super::Database::new(&path_string).await.unwrap();
        first
            .insert_peer("device01", b"device-uuid", &[9_u8; 32], &info)
            .await
            .unwrap();
        let connections = first.pool.retain(|_, _| false).removed;
        first.pool.close();
        drop(first);
        for connection in connections {
            connection.close().await.unwrap();
        }

        let reopened = super::Database::new(&path_string).await.unwrap();
        let stored = reopened.get_peer("device01").await.unwrap().unwrap();
        let restored: crate::peer::PeerInfo = serde_json::from_str(&stored.info).unwrap();
        assert_eq!(restored.ip, "192.0.2.10");
        assert_eq!(restored.deployment_generation, 7);

        let connections = reopened.pool.retain(|_, _| false).removed;
        reopened.pool.close();
        drop(reopened);
        for connection in connections {
            connection.close().await.unwrap();
        }
        let temporary_directory = directory.directory().to_owned();
        drop(directory);
        assert!(!temporary_directory.exists());
    }
}

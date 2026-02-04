use sqlx::{Pool, Postgres};

#[derive(Clone)]
pub struct Db {
    pool: Pool<Postgres>,
}

impl Db {
    pub fn new(pool: Pool<Postgres>) -> Self {
        Self { pool }
    }

    pub fn pool(&self) -> Pool<Postgres> {
        self.pool.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::outbound::db::error::Error;
    use sqlx::PgPool;

    #[sqlx::test]
    async fn test_new(pool: PgPool) -> Result<(), Error> {
        let db = Db::new(pool);
        let _pool = db.pool();

        Ok(())
    }
}

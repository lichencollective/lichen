use sqlx::PgPool;

#[derive(Clone)]
pub struct Repository {
    pub(crate) pool: PgPool,
}

impl Repository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

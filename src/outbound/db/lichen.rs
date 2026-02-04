use crate::domain::lichen::{
    CreateProjectDBParams, DatabaseRepository, FindProjectDBParams, Project,
};
use crate::outbound::db::error::Error;
use crate::outbound::db::models::{ProjectRow, ProjectRowList};
use crate::outbound::db::repository::Repository;
use async_trait::async_trait;
use uuid::Uuid;

#[async_trait]
impl DatabaseRepository for Repository {
    async fn create_project(
        &self,
        params: CreateProjectDBParams,
    ) -> Result<Project, crate::outbound::db::error::Error> {
        let result = sqlx::query_as::<_, ProjectRow>(
            "insert into projects (id, name, team_id) values ($1, $2, $3) returning *",
        )
        .bind(Uuid::now_v7())
        .bind(params.name)
        .bind(params.team_id)
        .fetch_one(&self.pool)
        .await;

        match result {
            Ok(row) => Ok(row.into()),
            Err(err) => {
                if let Some(database_error) = err.as_database_error()
                    && database_error.is_unique_violation()
                {
                    return Err(Error::OnConflict);
                }

                Err(Error::DatabaseError(err))
            }
        }
    }
    async fn list_projects(&self) -> Result<Vec<Project>, crate::outbound::db::error::Error> {
        let result = sqlx::query_as!(
            ProjectRow,
            r#"
select
    p.*
from projects p
"#
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(ProjectRowList(result).into())
    }

    async fn find_project_by_id(
        &self,
        params: FindProjectDBParams,
    ) -> Result<Option<Project>, crate::outbound::db::error::Error> {
        let result = sqlx::query_as!(
            ProjectRow,
            r#"
select
    p.*
from projects p
where id = $1
"#,
            params.project_id
        )
        .fetch_optional(&self.pool)
        .await?
        .map(|row| row.into());

        Ok(result)
    }
}

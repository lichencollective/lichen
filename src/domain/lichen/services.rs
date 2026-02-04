use crate::domain::lichen::{
    DatabaseRepository, FindProjectDBParams, GetProjectByIDResult, GetProjectByIDServiceParams,
    GetProjectByIdError, GetProjectsError, GetProjectsResult, LichenService,
};
use async_trait::async_trait;

#[derive(Debug, Clone)]
pub struct Service<DB>
where
    DB: DatabaseRepository,
{
    db: DB,
}

impl<DB> Service<DB>
where
    DB: DatabaseRepository,
{
    pub fn new(db: DB) -> Self {
        Self { db }
    }
}

#[async_trait]
impl<DB> LichenService for Service<DB>
where
    DB: DatabaseRepository,
{
    async fn get_projects(&self) -> Result<GetProjectsResult, GetProjectsError> {
        let projects = self.db.list_projects().await?;

        Ok(GetProjectsResult { projects })
    }

    async fn get_project_by_id(
        &self,
        params: GetProjectByIDServiceParams,
    ) -> Result<GetProjectByIDResult, GetProjectByIdError> {
        let project = self
            .db
            .find_project_by_id(FindProjectDBParams {
                project_id: params.project_id,
            })
            .await?;

        Ok(GetProjectByIDResult { project })
    }
}

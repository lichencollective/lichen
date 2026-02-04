use crate::domain::lichen::Project;
use crate::outbound::db::error::Error as DatabaseError;
use async_trait::async_trait;
use thiserror::Error;
use uuid::Uuid;

#[async_trait]
#[cfg_attr(test, mockall::automock)]
pub trait LichenService: Send + Sync {
    async fn get_projects(&self) -> Result<GetProjectsResult, GetProjectsError>;
    async fn get_project_by_id(
        &self,
        params: GetProjectByIDServiceParams,
    ) -> Result<GetProjectByIDResult, GetProjectByIdError>;
}

//------------------------------------------------------------------------------
// Get Projects
//------------------------------------------------------------------------------

pub struct GetProjectsResult {
    pub projects: Vec<Project>,
}

#[derive(Debug, Error)]
pub enum GetProjectsError {
    #[error("failed to get projects because of database error")]
    DatabaseError(#[from] DatabaseError),
}

//------------------------------------------------------------------------------
// Get Project by ID
//------------------------------------------------------------------------------

pub struct GetProjectByIDServiceParams {
    pub project_id: Uuid,
}

pub struct GetProjectByIDResult {
    pub project: Option<Project>,
}

#[derive(Debug, Error)]
pub enum GetProjectByIdError {
    #[error("failed to get project because of database error")]
    DatabaseError(#[from] DatabaseError),
}

////////////////////////////////////////////////////////////////////////////////////////////////////
// Database Repository
////////////////////////////////////////////////////////////////////////////////////////////////////

#[async_trait]
#[cfg_attr(test, mockall::automock)]
pub trait DatabaseRepository: Send + Sync + 'static {
    async fn create_project(&self, params: CreateProjectDBParams)
    -> Result<Project, DatabaseError>;

    async fn list_projects(&self) -> Result<Vec<Project>, DatabaseError>;
    async fn find_project_by_id(
        &self,
        params: FindProjectDBParams,
    ) -> Result<Option<Project>, DatabaseError>;
}

//------------------------------------------------------------------------------
// Create Project
//------------------------------------------------------------------------------

pub struct CreateProjectDBParams {
    pub team_id: Uuid,
    pub name: String,
}

//------------------------------------------------------------------------------
// Find Project
//------------------------------------------------------------------------------

pub struct FindProjectDBParams {
    pub project_id: Uuid,
}

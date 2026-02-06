use crate::domain::lichen::{Project, Team, TeamGroup};
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
    async fn create_team(&self, params: CreateTeamDBParams) -> Result<Team, DatabaseError>;
    async fn update_team(&self, params: UpdateTeamDBParams) -> Result<Team, DatabaseError>;
    async fn delete_team(&self, params: DeleteTeamDBParams) -> Result<(), DatabaseError>;
    async fn list_teams(&self) -> Result<Vec<Team>, DatabaseError>;

    async fn find_team_by_id(
        &self,
        params: FindTeamDBParams,
    ) -> Result<Option<Team>, DatabaseError>;

    async fn create_team_group(
        &self,
        params: CreateTeamGroupDBParams,
    ) -> Result<TeamGroup, DatabaseError>;
    async fn update_team_group(
        &self,
        params: UpdateTeamGroupDBParams,
    ) -> Result<TeamGroup, DatabaseError>;
    async fn delete_team_group(&self, params: DeleteTeamGroupDBParams)
    -> Result<(), DatabaseError>;
    async fn list_teams_group(
        &self,
        params: ListTeamGroupDBParams,
    ) -> Result<Vec<TeamGroup>, DatabaseError>;

    async fn find_team_group_by_id(
        &self,
        params: FindTeamGroupDBParams,
    ) -> Result<Option<TeamGroup>, DatabaseError>;

    async fn create_project(&self, params: CreateProjectDBParams)
    -> Result<Project, DatabaseError>;

    async fn update_project(&self, params: UpdateProjectDBParams)
    -> Result<Project, DatabaseError>;

    async fn delete_project(&self, params: DeleteProjectDBParams) -> Result<(), DatabaseError>;

    async fn list_projects(&self) -> Result<Vec<Project>, DatabaseError>;
    async fn find_project_by_id(
        &self,
        params: FindProjectDBParams,
    ) -> Result<Option<Project>, DatabaseError>;
}

//------------------------------------------------------------------------------
// Create Team
//------------------------------------------------------------------------------

pub struct CreateTeamDBParams {
    pub name: String,
}

//------------------------------------------------------------------------------
// Update Team
//------------------------------------------------------------------------------

pub struct UpdateTeamDBParams {
    pub team_id: Uuid,
    pub name: String,
}

//------------------------------------------------------------------------------
// Delete Team
//------------------------------------------------------------------------------

pub struct DeleteTeamDBParams {
    pub team_id: Uuid,
}

//------------------------------------------------------------------------------
// Find Team by ID
//------------------------------------------------------------------------------

pub struct FindTeamDBParams {
    pub team_id: Uuid,
}

//------------------------------------------------------------------------------
// Create Team Group
//------------------------------------------------------------------------------

pub struct CreateTeamGroupDBParams {
    pub team_id: Uuid,
    pub external_id: String,
    pub name: String,
    pub role: String,
}

//------------------------------------------------------------------------------
// Update Team Group
//------------------------------------------------------------------------------

pub struct UpdateTeamGroupDBParams {
    pub team_group_id: Uuid,
    pub external_id: String,
    pub name: String,
    pub role: String,
}

//------------------------------------------------------------------------------
// Delete Team Group
//------------------------------------------------------------------------------

pub struct DeleteTeamGroupDBParams {
    pub team_group_id: Uuid,
}

//------------------------------------------------------------------------------
// List Team Groups
//------------------------------------------------------------------------------

pub struct ListTeamGroupDBParams {
    pub team_id: Uuid,
}

//------------------------------------------------------------------------------
// Find Team Group by ID
//------------------------------------------------------------------------------

pub struct FindTeamGroupDBParams {
    pub team_group_id: Uuid,
}

//------------------------------------------------------------------------------
// Create Project
//------------------------------------------------------------------------------

pub struct CreateProjectDBParams {
    pub team_id: Uuid,
    pub name: String,
}

//------------------------------------------------------------------------------
// Update Project
//------------------------------------------------------------------------------

pub struct UpdateProjectDBParams {
    pub project_id: Uuid,
    pub name: String,
}

//------------------------------------------------------------------------------
// Delete Project
//------------------------------------------------------------------------------

pub struct DeleteProjectDBParams {
    pub project_id: Uuid,
}

//------------------------------------------------------------------------------
// Find Project
//------------------------------------------------------------------------------

pub struct FindProjectDBParams {
    pub project_id: Uuid,
}

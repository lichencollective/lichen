use crate::domain::lichen::{
    CreateProjectDBParams, CreateTeamDBParams, CreateTeamGroupDBParams, DatabaseRepository,
    DeleteProjectDBParams, DeleteTeamDBParams, DeleteTeamGroupDBParams, FindProjectDBParams,
    FindTeamDBParams, FindTeamGroupDBParams, ListTeamGroupDBParams, Project, Team, TeamGroup,
    UpdateProjectDBParams, UpdateTeamDBParams, UpdateTeamGroupDBParams,
};
use crate::outbound::db::error::Error;
use crate::outbound::db::models::{
    ProjectRow, ProjectRowList, TeamGroupRow, TeamGroupRowList, TeamRow, TeamRowList,
};
use crate::outbound::db::repository::Repository;
use async_trait::async_trait;
use uuid::Uuid;

#[async_trait]
impl DatabaseRepository for Repository {
    async fn create_team(
        &self,
        params: CreateTeamDBParams,
    ) -> Result<Team, crate::outbound::db::error::Error> {
        let result = sqlx::query_as::<_, TeamRow>(
            "insert into teams (id, name) values ($1, $2) returning *",
        )
        .bind(Uuid::now_v7())
        .bind(params.name)
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
    async fn update_team(
        &self,
        params: UpdateTeamDBParams,
    ) -> Result<Team, crate::outbound::db::error::Error> {
        let row = sqlx::query_as!(
            TeamRow,
            r#"
update teams set name=$2
where id = $1
returning *
"#,
            params.team_id,
            params.name
        )
        .fetch_one(&self.pool)
        .await?;

        Ok(row.into())
    }

    async fn delete_team(
        &self,
        params: DeleteTeamDBParams,
    ) -> Result<(), crate::outbound::db::error::Error> {
        sqlx::query("delete from teams where id = $1")
            .bind(params.team_id)
            .execute(&self.pool)
            .await?;

        Ok(())
    }
    async fn list_teams(&self) -> Result<Vec<Team>, crate::outbound::db::error::Error> {
        let result = sqlx::query_as!(
            TeamRow,
            r#"
select
    t.*
from teams t
"#
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(TeamRowList(result).into())
    }

    async fn find_team_by_id(
        &self,
        params: FindTeamDBParams,
    ) -> Result<Option<Team>, crate::outbound::db::error::Error> {
        let result = sqlx::query_as!(
            TeamRow,
            r#"
select
    t.*
from teams t
where id = $1
"#,
            params.team_id
        )
        .fetch_optional(&self.pool)
        .await?
        .map(|row| row.into());

        Ok(result)
    }

    async fn create_team_group(
        &self,
        params: CreateTeamGroupDBParams,
    ) -> Result<TeamGroup, crate::outbound::db::error::Error> {
        let result = sqlx::query_as::<_, TeamGroupRow>(
            "insert into team_groups (id, team_id, external_id, name, role) values ($1, $2, $3, $4, $5) returning *",

        )
            .bind(Uuid::now_v7())
            .bind(params.team_id)
            .bind(params.external_id)
            .bind(params.name)
            .bind(params.role)
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

    async fn update_team_group(
        &self,
        params: UpdateTeamGroupDBParams,
    ) -> Result<TeamGroup, crate::outbound::db::error::Error> {
        let row = sqlx::query_as!(
            TeamGroupRow,
            r#"
update team_groups set external_id=$2, name=$3, role=$4
where id = $1
returning *
"#,
            params.team_group_id,
            params.external_id,
            params.name,
            params.role
        )
        .fetch_one(&self.pool)
        .await?;

        Ok(row.into())
    }

    async fn delete_team_group(
        &self,
        params: DeleteTeamGroupDBParams,
    ) -> Result<(), crate::outbound::db::error::Error> {
        sqlx::query("delete from team_groups where id = $1")
            .bind(params.team_group_id)
            .execute(&self.pool)
            .await?;

        Ok(())
    }

    async fn list_teams_group(
        &self,
        params: ListTeamGroupDBParams,
    ) -> Result<Vec<TeamGroup>, crate::outbound::db::error::Error> {
        let result = sqlx::query_as!(
            TeamGroupRow,
            r#"
select
    g.*
from team_groups g
where g.team_id = $1
"#,
            params.team_id,
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(TeamGroupRowList(result).into())
    }

    async fn find_team_group_by_id(
        &self,
        params: FindTeamGroupDBParams,
    ) -> Result<Option<TeamGroup>, crate::outbound::db::error::Error> {
        let result = sqlx::query_as!(
            TeamGroupRow,
            r#"
select
    g.*
from team_groups g
where id = $1
"#,
            params.team_group_id
        )
        .fetch_optional(&self.pool)
        .await?
        .map(|row| row.into());

        Ok(result)
    }

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

    async fn update_project(
        &self,
        params: UpdateProjectDBParams,
    ) -> Result<Project, crate::outbound::db::error::Error> {
        let row = sqlx::query_as!(
            ProjectRow,
            r#"
update projects set name=$2
where id = $1
returning *
"#,
            params.project_id,
            params.name
        )
        .fetch_one(&self.pool)
        .await?;

        Ok(row.into())
    }

    async fn delete_project(
        &self,
        params: DeleteProjectDBParams,
    ) -> Result<(), crate::outbound::db::error::Error> {
        sqlx::query("delete from projects where id = $1")
            .bind(params.project_id)
            .execute(&self.pool)
            .await?;

        Ok(())
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

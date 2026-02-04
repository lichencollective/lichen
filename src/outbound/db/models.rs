use crate::domain::lichen::Project;
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use time::PrimitiveDateTime;
use uuid::Uuid;

#[derive(FromRow, Clone, Serialize, Deserialize)]
pub struct ProjectRow {
    pub id: Uuid,
    pub name: String,
    pub team_id: Uuid,
    pub tags: serde_json::Value,
    pub created_at: PrimitiveDateTime,
    pub updated_at: PrimitiveDateTime,
}

impl From<ProjectRow> for Project {
    fn from(value: ProjectRow) -> Self {
        Self {
            id: value.id,
            team_id: value.team_id,
            name: value.name,
            created_at: value.created_at,
            updated_at: value.updated_at,
        }
    }
}

pub struct ProjectRowList(pub Vec<ProjectRow>);

impl From<ProjectRowList> for Vec<Project> {
    fn from(value: ProjectRowList) -> Self {
        value.0.into_iter().map(|row| row.into()).collect()
    }
}

#[derive(FromRow, Clone)]
pub struct TeamRow {
    pub id: Uuid,
    pub name: String,
    pub created_at: PrimitiveDateTime,
    pub updated_at: PrimitiveDateTime,
}

#[derive(FromRow, Clone)]
pub struct TeamGroupRow {
    pub id: Uuid,
    pub name: String,
    pub team_id: Uuid,
    pub created_at: PrimitiveDateTime,
    pub updated_at: PrimitiveDateTime,
}

pub struct TeamGroupRowList(pub Vec<TeamGroupRow>);

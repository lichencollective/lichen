use time::PrimitiveDateTime;
use uuid::Uuid;

#[derive(Clone)]
pub struct Project {
    pub id: Uuid,
    pub name: String,
    pub team_id: Uuid,
    pub created_at: PrimitiveDateTime,
    pub updated_at: PrimitiveDateTime,
}

#[derive(Clone)]
pub struct Team {
    pub id: Uuid,
    pub name: String,
    pub created_at: PrimitiveDateTime,
    pub updated_at: PrimitiveDateTime,
}

#[derive(Clone)]
pub struct TeamGroup {
    pub id: Uuid,
    pub name: String,
    pub created_at: PrimitiveDateTime,
    pub updated_at: PrimitiveDateTime,
}

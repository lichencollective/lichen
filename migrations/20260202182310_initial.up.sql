CREATE OR REPLACE FUNCTION update_timestamp()
    RETURNS TRIGGER AS
$$
BEGIN
    NEW.updated_at = current_timestamp;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TABLE teams
(
    id         uuid        not null primary key,
    name       varchar(255)        not null,

    created_at    timestamp    not null default current_timestamp,
    updated_at    timestamp    not null default current_timestamp
);

CREATE TRIGGER update_teams_updated_at
    BEFORE UPDATE
    ON teams
    FOR EACH ROW
EXECUTE FUNCTION update_timestamp();

CREATE TABLE team_groups
(
    id         uuid        not null primary key,
    team_id    uuid not null,
    name       varchar(255)        not null,

    created_at    timestamp    not null default current_timestamp,
    updated_at    timestamp    not null default current_timestamp
);

CREATE TRIGGER update_team_groups_updated_at
    BEFORE UPDATE
    ON team_groups
    FOR EACH ROW
EXECUTE FUNCTION update_timestamp();

CREATE TABLE projects
(
    id         uuid        not null primary key,
    name       varchar(255)        not null,
    team_id    uuid        not null,

    tags       JSONB       NOT NULL DEFAULT '{}'::jsonb,

    created_at    timestamp    not null default current_timestamp,
    updated_at    timestamp    not null default current_timestamp,

    constraint fk_projects_team_id foreign key (team_id) references teams (id) on delete cascade
);

CREATE TRIGGER update_projects_updated_at
    BEFORE UPDATE
    ON projects
    FOR EACH ROW
EXECUTE FUNCTION update_timestamp();

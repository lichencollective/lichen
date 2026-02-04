-- Add down migration script here
DROP TABLE IF EXISTS projects;
DROP TABLE IF EXISTS team_groups;
DROP TABLE IF EXISTS teams;

drop function if exists update_timestamp();

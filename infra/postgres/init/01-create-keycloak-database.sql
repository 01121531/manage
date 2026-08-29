-- The image entrypoint runs this only on an empty PostgreSQL data volume.
-- The following init script creates Keycloak's restricted login and transfers
-- this database to it before PostgreSQL becomes healthy.
CREATE DATABASE keycloak;

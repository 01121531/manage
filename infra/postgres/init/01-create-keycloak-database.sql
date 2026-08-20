-- The image entrypoint runs this only on an empty PostgreSQL data volume.
-- Keycloak uses the same bootstrap database role in this development compose
-- topology. Production must provision a separate least-privilege role.
CREATE DATABASE keycloak;

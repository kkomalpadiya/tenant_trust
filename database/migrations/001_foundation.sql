CREATE SCHEMA IF NOT EXISTS identity;
CREATE SCHEMA IF NOT EXISTS trust;
CREATE SCHEMA IF NOT EXISTS audit;

COMMENT ON SCHEMA identity IS 'Tenant identities, credentials and certificate lifecycle data';
COMMENT ON SCHEMA trust IS 'Trust signals, scores, policy decisions and supporting evidence';
COMMENT ON SCHEMA audit IS 'Queryable application audit projections; authoritative evidence may also be anchored to Fabric';

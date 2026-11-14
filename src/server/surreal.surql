-- g3-payments' tables (feature `surreal`). Every row carries its app, so
-- several apps share one database. Additive only: an older server must keep
-- running against a newer schema.

DEFINE TABLE IF NOT EXISTS pay_purchase SCHEMAFULL;
DEFINE FIELD IF NOT EXISTS app ON pay_purchase TYPE string;
DEFINE FIELD IF NOT EXISTS provider ON pay_purchase TYPE string;
-- The provider's stable id for the purchase; refs holds it and every alias.
DEFINE FIELD IF NOT EXISTS purchase_id ON pay_purchase TYPE string;
DEFINE FIELD IF NOT EXISTS refs ON pay_purchase TYPE array<string>;
-- The app's owner id; on the license server, the license key.
DEFINE FIELD IF NOT EXISTS owner ON pay_purchase TYPE string;
DEFINE FIELD IF NOT EXISTS product ON pay_purchase TYPE string;
DEFINE FIELD IF NOT EXISTS status ON pay_purchase TYPE string ASSERT $value IN ['active', 'revoked'];
DEFINE FIELD IF NOT EXISTS expires_at ON pay_purchase TYPE option<int>;
DEFINE FIELD IF NOT EXISTS event_created ON pay_purchase TYPE int;
DEFINE INDEX IF NOT EXISTS pay_purchase_id ON pay_purchase FIELDS app, provider, purchase_id UNIQUE;
DEFINE INDEX IF NOT EXISTS pay_purchase_owner ON pay_purchase FIELDS app, owner;

-- A change that arrived before its purchase (a refund before its checkout).
DEFINE TABLE IF NOT EXISTS pay_pending SCHEMAFULL;
DEFINE FIELD IF NOT EXISTS app ON pay_pending TYPE string;
DEFINE FIELD IF NOT EXISTS provider ON pay_pending TYPE string;
DEFINE FIELD IF NOT EXISTS purchase_id ON pay_pending TYPE string;
DEFINE FIELD IF NOT EXISTS status ON pay_pending TYPE string ASSERT $value IN ['active', 'revoked'];
DEFINE FIELD IF NOT EXISTS expires_at ON pay_pending TYPE option<int>;
DEFINE FIELD IF NOT EXISTS event_created ON pay_pending TYPE int;
DEFINE INDEX IF NOT EXISTS pay_pending_id ON pay_pending FIELDS app, provider, purchase_id UNIQUE;

-- Provider events already handled.
DEFINE TABLE IF NOT EXISTS pay_event SCHEMAFULL;
DEFINE FIELD IF NOT EXISTS app ON pay_event TYPE string;
DEFINE FIELD IF NOT EXISTS provider ON pay_event TYPE string;
DEFINE FIELD IF NOT EXISTS event_id ON pay_event TYPE string;
DEFINE FIELD IF NOT EXISTS handled_at ON pay_event TYPE datetime;
DEFINE INDEX IF NOT EXISTS pay_event_id ON pay_event FIELDS app, provider, event_id UNIQUE;

-- The machines a license key is active on, by the key's id (never the key).
DEFINE TABLE IF NOT EXISTS license_activation SCHEMAFULL;
DEFINE FIELD IF NOT EXISTS app ON license_activation TYPE string;
DEFINE FIELD IF NOT EXISTS key_id ON license_activation TYPE string;
DEFINE FIELD IF NOT EXISTS machine ON license_activation TYPE string;
DEFINE FIELD IF NOT EXISTS name ON license_activation TYPE string;
DEFINE FIELD IF NOT EXISTS activated_at ON license_activation TYPE int;
DEFINE INDEX IF NOT EXISTS license_activation_machine ON license_activation FIELDS app, key_id, machine UNIQUE;

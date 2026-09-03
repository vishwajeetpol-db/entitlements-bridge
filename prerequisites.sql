-- ============================================================================
-- prerequisites.sql — run ONCE, by a workspace/metastore admin, before deploying the bundle.
--
-- The bundle does NOT create the catalog or the schema. They are inputs you own and name, so the audit
-- data lands where your governance model says it should. The jobs only create their own tables inside
-- the schema you name here, and only ever append to them.
--
-- Replace ALL of the placeholders below and run in the governance workspace:
--   :catalog    the catalog that will hold the audit tables            e.g. entitlements_audit
--   :schema     the schema inside it                                   e.g. bridge
--   :runner_sp  the runner SP applicationId (UUID, not the numeric id) — runs tasks 1-3
--   :account_admin  the account-admin principal that runs task 0: an SP applicationId, or a user email
-- ============================================================================

-- ---- 1. destination -------------------------------------------------------
-- The catalog and schema are YOURS. This script does not create them for you by default, because where
-- audit data lives is a governance decision. Create them however your organisation normally does, then
-- run section 2. If you want to create them here, uncomment exactly ONE of (a) / (b) / (c) below.
--
-- WHICH ONE depends on your metastore. Check first:
--     GET /api/2.1/unity-catalog/metastore_summary     -> field `storage_root`
--
-- If `storage_root` is NULL, a bare CREATE CATALOG fails, and the platform's error names the remedies:
--     [INVALID_STATE] Metastore storage root URL does not exist. Default Storage is enabled in your
--     account. You can use the UI to create a new catalog using Default Storage, or please provide a
--     storage location for the catalog (for example 'CREATE CATALOG myCatalog MANAGED LOCATION
--     '<location-path>').
-- A null root is common and is the shape Databricks now uses for new metastores, so do not assume.

-- (a) metastore HAS a storage_root -- the simple form:
-- CREATE CATALOG IF NOT EXISTS :catalog;

-- (b) storage_root is NULL and Default Storage is enabled -- easiest path: create the catalog in the
--     Catalog Explorer UI and pick Default Storage. No location to find, nothing to type here.

-- (c) storage_root is NULL and you want an explicit location. Substitute the path INLINE -- a named
--     parameter is NOT expanded inside a quoted string, so ':managed_location' would be taken
--     literally. Replace the whole quoted value by hand:
-- CREATE CATALOG IF NOT EXISTS :catalog
--   MANAGED LOCATION 'abfss://<container>@<account>.dfs.core.windows.net/<path>';   -- Azure
--   -- MANAGED LOCATION 's3://<bucket>/<path>';                                     -- AWS

-- Then the schema (uncomment if you are creating it here):
-- CREATE SCHEMA  IF NOT EXISTS :catalog.:schema;

-- ---- 2. grants ---------------------------------------------------------------
-- Two identities, because the run is deliberately split across two privilege levels.
--
-- CREATE TABLE: the jobs create their nine tables on first run (ws_inventory plus eight outputs).
-- MODIFY:       they append to them on every later run.
-- SELECT:       plan reads back what audit wrote, and audit/apply read the inventory.

-- the runner SP — tasks 1-3. Workspace admin on the target workspaces, NO account access.
GRANT USE CATALOG                                ON CATALOG :catalog          TO `:runner_sp`;
GRANT USE SCHEMA, CREATE TABLE, MODIFY, SELECT   ON SCHEMA  :catalog.:schema  TO `:runner_sp`;

-- the account admin — task 0 only. It creates and populates ws_inventory, so it needs to write here too.
-- Skip these two if the same identity happens to own the schema.
GRANT USE CATALOG                                ON CATALOG :catalog          TO `:account_admin`;
GRANT USE SCHEMA, CREATE TABLE, MODIFY, SELECT   ON SCHEMA  :catalog.:schema  TO `:account_admin`;

-- ---- 2b. FOUR THINGS THE GRANTS ABOVE DO NOT COVER -------------------------
-- Task 0 runs as a DIFFERENT identity from tasks 1-3, and a job's run_as identity needs more than UC
-- privileges. All four were measured on 2026-09-02 by running task 0 as a real job; each one failed the
-- run with a different error until it was fixed, so none of them is theoretical.
--
-- (a) The account-admin identity must EXIST IN THE WORKSPACE where the jobs run. A principal that is an
--     account admin is not thereby a member of any workspace. Assign it (workspace USER is enough --
--     these are serverless jobs, so no cluster entitlement is needed):
--       PUT /api/2.0/accounts/{account_id}/workspaces/{workspace_id}/permissionassignments
--           /principals/{principal_id}     {"permissions": ["USER"]}
--     Symptom if missing: deploy fails 400 INVALID_PARAMETER_VALUE
--       "Invalid user: '<applicationId>' does not exist or deactivated".
--
-- (b) The identity that DEPLOYS the bundle needs `roles/servicePrincipal.user` ON the account-admin SP,
--     or it may not bind it as a job's run_as. Grant it on the SP's own rule set:
--       PUT /api/2.0/preview/accounts/{account_id}/access-control/rule-sets
--       name=accounts/{account_id}/servicePrincipals/{sp_applicationId}/ruleSets/default
--     preserving the existing grant_rules and adding the deployer as a principal of that role.
--     Symptom if missing: deploy fails 403 PERMISSION_DENIED "Cannot bind the service principal
--     provided in 'run_as' field ... must have 'servicePrincipal.user' role".
--     ⚠ That API is eventually consistent -- an immediate re-read can show a false negative.
--
-- (c) The account-admin identity needs READ on the secret scope holding its own OAuth credentials.
--     It cannot mint an account token without them, and scope ACLs are not implied by workspace access:
--       POST /api/2.0/secrets/acls/put  {"scope": "...", "principal": "<applicationId>",
--                                        "permission": "READ"}
--
-- (d) The account-admin identity needs to READ THE DEPLOYED BUNDLE ARTIFACTS. A bundle deploys under the
--     DEPLOYING identity's workspace home, so a job running as a different identity cannot see its own
--     notebook. Either grant CAN_READ on the bundle root:
--       PATCH /api/2.0/permissions/directories/{object_id}
--             {"access_control_list":[{"service_principal_name":"<applicationId>",
--                                      "permission_level":"CAN_READ"}]}
--     or -- cleaner where two run_as identities exist -- set the bundle's workspace.root_path to a
--     shared location both identities can read. Symptom if missing: run fails RESOURCE_NOT_FOUND
--     "Unable to access the notebook".
--
-- ⚠ SEPARATE THE SCOPES. `account_client_id_key` / `account_client_secret_key` default to the SAME
--    secret scope the runner SP reads, so any principal with READ on that scope can reach ACCOUNT ADMIN.
--    Put the account-admin credentials in their own scope whose ACL excludes the runner, and check the
--    scope's existing ACLs before you use it -- a scope granting MANAGE to `users` exposes those
--    credentials to every workspace user.

-- ---- 3. the workspace inventory is BUILT BY THE BUNDLE, not by you ----------
-- Nothing to do here. Task 0 (`entl_inventory`) creates and populates `:catalog.:schema.ws_inventory`
-- inside the schema above, then tasks 1-3 read it. You own the catalog and the schema; every table in
-- them is ours.
--
-- Task 0 is the only task that needs ACCOUNT-level access, and it is used once per cloud. Give it an
-- account-admin identity via the `account_admin_principal` bundle variable, and if you run it as a
-- service principal put that SP's OAuth credentials in the same secret scope under the keys named by
-- `account_client_id_key` / `account_client_secret_key`. Tasks 1-3 need no account access whatsoever --
-- that hand-off is the reason task 0 exists as a separate job.
--
-- By default task 0 changes nothing: it lists the workspaces in scope, reports whether the runner SP is
-- already a workspace admin on each, and writes the table. Set `grant_runner_workspace_admin=true` only
-- if you also want it to grant that permission.

-- ---- 4. check what the jobs will see --------------------------------------
-- Run this AFTER task 0 has populated the inventory. Before that the table does not exist yet, which is
-- expected — task 0 creates it.
SELECT cloud, count(*) AS workspaces FROM :catalog.:schema.ws_inventory GROUP BY cloud;

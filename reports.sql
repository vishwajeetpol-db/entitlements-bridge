-- ============================================================================
-- reports.sql — the hand-back reports. Read-only, safe to run at any time.
--
-- Run these in the governance workspace. `:catalog` and `:schema` are NAMED PARAMETERS: in the
-- Databricks SQL editor they appear as input boxes above the results — fill them in once and every
-- query in the file uses them. No find-and-replace needed. From the CLI or JDBC, substitute them.
-- Every table is append-only and stamped with run_id + run_ts, so "latest" always means the most
-- recent run and history is never overwritten. Re-running a job adds a generation; it never overwrites.
--
-- WHEN TO RUN WHAT
-- ----------------
-- There are three moments worth querying, not four: before the dry run NO tables exist yet (job 0
-- creates the first one), and "after the dry run" and "before the apply" are the same moment.
--
--   PHASE 1 — readiness, before any job has run
--     Nothing here applies: no tables exist. Use the pre-flight checklist in DEPLOYMENT.md §5, plus
--     SHOW GRANTS on your catalog and schema, and confirm the secret scope holds its four keys.
--
--   PHASE 2 — REVIEW, after jobs 0-2, before the apply.   This is the sign-off gate.
--     Everything the apply will do is already written down. Run, in this order:
--       report 5   one-line fleet summary          — is the shape what you expected?
--       report 2   skipped workspaces + reason     — the separate list to review
--       report 7   WHAT WILL CHANGE, one row each  — groups and identities together
--       report 1   pre-change entitlements         — the as-found state, for the record
--       report 4   identities no group can reach    — who depends on the direct path
--     Nothing has been modified at this point. Re-run jobs 1-2 freely.
--
--   PHASE 3 — VERIFICATION, after the apply
--       report 7   WHAT CHANGED, same query        — now carries the outcome columns
--       report 3   before -> after per group        — the group audit trail
--       report 6   per-identity decision + outcome  — the identity audit trail
--       report 5   fleet summary again              — compare against phase 2
--     Then verify against the estate itself, not these tables — DEPLOYMENT.md §8.
--
-- On a clean run `http_error` is empty in every row of reports 3, 6 and 7 -- that is the healthy case,
-- not a missing column. It carries text only where a write failed.
--
-- Report 7 is the one to hand to a change board: one row per object, what it held, what was added,
-- and whether the write was confirmed by re-read.
-- ============================================================================

-- ---------------------------------------------------------------------------
-- 1. PRE-CHANGE ENTITLEMENTS, per group per workspace.
--    The as-found state, before anything was granted. Take this from the audit run you did BEFORE
--    the apply; it is the record of what every group held going in.
-- ---------------------------------------------------------------------------
SELECT
  g.workspace_id,
  m.host,
  g.display_name                AS group_name,
  g.classification,             -- aad_account_group | native_account_group | workspace_local_group | system_group | migration_clone_group
  g.external_id,                -- the Entra objectId for IdP-synced groups
  g.entitlements                AS entitlements_before,
  g.has_workspace_access,
  g.has_sql_access,
  g.member_count,
  g.run_ts
FROM :catalog.:schema.group_state g
JOIN :catalog.:schema.ws_migration_state m
  ON m.workspace_id = g.workspace_id AND m.run_ts = g.run_ts
WHERE g.run_ts = (SELECT max(run_ts) FROM :catalog.:schema.group_state)
ORDER BY g.workspace_id, g.classification, g.display_name;


-- ---------------------------------------------------------------------------
-- 2. SKIPPED WORKSPACES, with the reason. This is the separate list to review.
--    USERS_MISSING_BOTH / _SQL / _WORKSPACE  = the users group does not hold both entitlements,
--                                              so there is nothing safe to propagate.
--    ALREADY_MIGRATED                        = the workspace is already on the new behaviour; its
--                                              clone group holds the entitlements. Handle in IaC.
--    NOT_ADMIN                               = the runner SP is not a workspace admin there.
--    USERS_GROUP_NOT_FOUND / WORKSPACE_READ_FAILED = could not establish the state; never guessed.
-- ---------------------------------------------------------------------------
SELECT
  v.workspace_id,
  v.host,
  v.cloud,
  v.reason                      AS skip_reason,
  v.migration_state,
  v.migration_reason,           -- CUSTOMER = someone opted in/out. PHASE_2 = the Databricks auto-enable wave.
  v.users_entitlements,         -- what the users group actually held, which is why it was skipped
  v.groups_total,
  v.principals_access_only_via_users
FROM :catalog.:schema.ws_verdict v
WHERE v.run_ts = (SELECT max(run_ts) FROM :catalog.:schema.ws_verdict)
  AND v.verdict = 'SKIP'
ORDER BY v.reason, v.workspace_id;


-- ---------------------------------------------------------------------------
-- 3. BEFORE -> AFTER, per group actually written. The audit trail for the change.
--    `verified` is a re-read after the PATCH, not the PATCH's own status code: a no-op write returns
--    success, so a 2xx alone is not proof anything was applied.
-- ---------------------------------------------------------------------------
SELECT
  a.workspace_id,
  a.host,
  a.display_name                AS group_name,
  a.classification,
  a.entitlements_before,
  a.added,
  a.entitlements_after,
  a.status,                     -- GRANTED | NOOP | FAILED* | ABANDONED_* | FAILED_ENTITLEMENT_LOSS
  a.verified,
  a.http_error,
  a.run_ts
FROM :catalog.:schema.apply_outcome a
WHERE a.run_ts = (SELECT max(run_ts) FROM :catalog.:schema.apply_outcome)
ORDER BY a.status, a.workspace_id, a.display_name;


-- ---------------------------------------------------------------------------
-- 4. PRINCIPALS A GROUP GRANT CANNOT REACH.
--    Users and service principals whose workspace access today comes ONLY from the `users` system
--    group -- not from any account group. Granting entitlements to groups cannot help them, because
--    they are not in one. At migration they are moved into the clone group and keep their access, so
--    the operational rule is: do not empty the `users` group before the change lands.
--    Review this list; anyone who should have durable access needs a group membership or a direct grant.
-- ---------------------------------------------------------------------------
SELECT
  p.workspace_id,
  p.principal_type,             -- USER | SERVICE_PRINCIPAL
  p.identifier,                 -- userName, or applicationId for a service principal
  p.display_name,
  p.active,
  p.direct_entitlements,
  -- `groups` is EMPTY for every row here by definition -- that is what puts the identity in this report.
  -- Rendering the raw array left the column blank in every row, which told the reader nothing, so state it.
  -- (SCIM does not report `users` in a principal's own groups attribute, so [] means "only `users`".)
  coalesce(nullif(concat_ws(', ', p.groups), ''),
           'in no group but `users`')                AS groups_held,
  p.effective_entitlements
FROM :catalog.:schema.principal_state p
WHERE p.run_ts = (SELECT max(run_ts) FROM :catalog.:schema.principal_state)
  AND p.access_only_via_users = true
ORDER BY p.workspace_id, p.principal_type, p.identifier;


-- ---------------------------------------------------------------------------
-- 5. One-line fleet summary, for the status update.
-- ---------------------------------------------------------------------------
SELECT
  verdict,
  reason,
  count(*)                          AS workspaces,
  sum(groups_to_grant)              AS groups_to_grant,
  sum(groups_already_correct)       AS groups_already_correct,
  sum(principals_access_only_via_users) AS principals_only_via_users,
  sum(principals_to_grant)          AS principals_to_grant,
  sum(principals_already_correct)   AS principals_already_correct,
  sum(principals_admin_excluded)    AS principals_admin_excluded
FROM :catalog.:schema.ws_verdict
WHERE run_ts = (SELECT max(run_ts) FROM :catalog.:schema.ws_verdict)
GROUP BY verdict, reason
ORDER BY verdict, workspaces DESC;


-- ---------------------------------------------------------------------------
-- 6. THE PER-IDENTITY PATH, decision and outcome side by side.
--    Report 1 covers groups. This covers the identities a group grant cannot reach: a non-admin user or
--    service principal whose only group is `users`.
--    ADMINS APPEAR HERE ON PURPOSE, as SKIP / ADMIN_INHERITS_VIA_ADMINS_GROUP. They are never written to
--    — they hold all five workspace entitlement flags through `admins`, which this tool does not modify — and
--    listing them is what proves they were considered and excluded rather than simply missed.
--    apply_status is NULL until task 3 has run. direct_principals_mode records which mode produced the row.
-- ---------------------------------------------------------------------------
SELECT
  pa.workspace_id,
  pa.principal_type,            -- user | service_principal
  pa.identifier,
  pa.display_name,
  pa.is_admin,
  -- empty for every in-scope row by definition; spelled out rather than left blank (see report 4)
  coalesce(nullif(concat_ws(', ', pa.reachable_groups), ''),
           'none — no group grant can reach it')     AS reachable_groups,
  pa.entitlements_before,
  pa.missing,                   -- what a GRANT adds
  pa.action,                    -- GRANT | NOOP | SKIP
  pa.reason,
  pa.direct_principals_mode,    -- grant | skip
  ao.status                     AS apply_status,
  ao.added                      AS apply_added,
  ao.entitlements_after,
  ao.verified                   -- verified by re-read, not by the PATCH returning 2xx
FROM :catalog.:schema.principal_action pa
LEFT JOIN :catalog.:schema.apply_outcome ao
  ON  ao.workspace_id  = pa.workspace_id
  AND ao.principal_id  = pa.principal_id
  AND ao.target_type   = 'principal'
  AND ao.run_ts = (SELECT max(run_ts) FROM :catalog.:schema.apply_outcome)
WHERE pa.run_ts = (SELECT max(run_ts) FROM :catalog.:schema.principal_action)
ORDER BY pa.workspace_id, pa.action, pa.principal_type, pa.identifier;


-- ---------------------------------------------------------------------------
-- 7. WHAT WILL CHANGE / WHAT CHANGED — one row per object, groups and identities together.
--    Run it in PHASE 2 to review, and again in PHASE 3 to verify. The same query serves both: before
--    the apply the outcome columns are NULL, after it they carry the result.
--    Reports 1, 3, 4 and 6 slice this by object type; this is the single list.
--    `planned_action = 'GRANT'` is the exact and complete set of objects the apply touches.
-- ---------------------------------------------------------------------------
WITH groups AS (
  SELECT
    ga.workspace_id,
    'group'                      AS object_type,
    ga.display_name              AS object_name,
    ga.classification            AS detail,
    ga.entitlements_before,
    ga.missing                   AS will_add,
    ga.action                    AS planned_action,
    ga.reason                    AS planned_reason
  FROM :catalog.:schema.group_action ga
  WHERE ga.run_ts = (SELECT max(run_ts) FROM :catalog.:schema.group_action)
),
principals AS (
  SELECT
    pa.workspace_id,
    pa.principal_type            AS object_type,
    pa.identifier                AS object_name,
    -- nullif() matters: concat_ws on an EMPTY array returns '', not NULL, so a bare coalesce()
    -- never fires and the most important row in this report -- an identity in no group but `users`,
    -- which is exactly why the direct path exists -- rendered as "groups:" with nothing after it.
    CASE WHEN pa.is_admin THEN 'admin — never written to'
         ELSE coalesce(concat('member of: ', nullif(concat_ws(', ', pa.reachable_groups), '')),
                       'in no group but `users` — no group grant can reach it')
    END                          AS detail,
    pa.entitlements_before,
    pa.missing                   AS will_add,
    pa.action                    AS planned_action,
    pa.reason                    AS planned_reason
  FROM :catalog.:schema.principal_action pa
  WHERE pa.run_ts = (SELECT max(run_ts) FROM :catalog.:schema.principal_action)
),
planned AS (SELECT * FROM groups UNION ALL SELECT * FROM principals),
outcome AS (
  SELECT workspace_id, target_type, display_name, identifier, status, added,
         entitlements_after, verified, http_error
  FROM :catalog.:schema.apply_outcome
  WHERE run_ts = (SELECT max(run_ts) FROM :catalog.:schema.apply_outcome)
)
SELECT
  v.workspace_name,
  p.workspace_id,
  p.object_type,                    -- group | user | service_principal
  p.object_name,
  p.detail,
  v.verdict                     AS workspace_verdict,
  p.entitlements_before,
  p.will_add,
  p.planned_action,                 -- GRANT | NOOP | SKIP | OUT_OF_SCOPE
  p.planned_reason,
  o.status                      AS apply_status,        -- NULL until the apply has run
  o.added                       AS actually_added,
  o.entitlements_after,
  o.verified,                                            -- confirmed by re-read, not by a 2xx
  o.http_error
FROM planned p
LEFT JOIN :catalog.:schema.ws_verdict v
       ON  v.workspace_id = p.workspace_id
       AND v.run_ts = (SELECT max(run_ts) FROM :catalog.:schema.ws_verdict)
LEFT JOIN outcome o
       ON  o.workspace_id = p.workspace_id
       AND (   (p.object_type = 'group' AND o.target_type = 'group'     AND o.display_name = p.object_name)
            OR (p.object_type <> 'group' AND o.target_type = 'principal' AND o.identifier   = p.object_name))
ORDER BY p.planned_action, v.workspace_name, p.object_type, p.object_name;

# Entitlements bridge — grant Workspace + SQL access to AAD groups before the system-groups change

A Databricks Asset Bundle that prepares a fleet of workspaces for the **"Choose entitlements when adding
principals to workspaces"** behaviour change (enforced for all workspaces on **14 September 2026**).

Until that change, every principal added to a workspace joins the built-in `users` system group, and `users`
grants **Workspace access** and **Databricks SQL access** by default — so every member effectively holds both,
whether or not anything was ever set on their own group. After the change, `users` carries no entitlements and
each principal's entitlements must be explicit.

This bundle makes that implicit grant **explicit on your AAD groups**, so access does not depend on the
`users` group any more.

---

## 1. Scope — what it touches, and what it never touches

**Grants** `workspace-access` + `databricks-sql-access` to two populations in each workspace:

1. **AAD-synced account groups** — the main path.
2. **Identities no group grant can reach** — a **non-admin** user or service principal whose only group is
   `users`. Without this they would be entitled by nothing after migration, because they are in no group for
   a group grant to flow through. Controlled by `direct_principals` (`grant` by default, `skip` restricts the
   run to groups alone).

**Admin users and service principals are never written to, in either mode.** Membership of `admins` already
carries **all five** workspace entitlement flags — `workspace-consume`, `workspace-access`,
`databricks-sql-access`, `allow-cluster-create`, `allow-instance-pool-create` — and `admins` is never
modified, so an admin needs nothing from this tool. They
are still listed in the report, as `SKIP / ADMIN_INHERITS_VIA_ADMINS_GROUP`, so you can see they were
considered and excluded rather than overlooked.

**Never modifies:**
- the `users` system group — deliberately left exactly as it is (see §7, this is load-bearing)
- the `admins` system group, or any identity that is a member of it
- `users-clone-*` groups created by Databricks
- any entitlement other than the two above — `allow-cluster-create` and `allow-instance-pool-create` are
  never added and never removed
- group **membership** — only entitlements

**Audits but does not grant to:** Databricks-native account groups and legacy workspace-local groups. Both are
counted and listed in the report so the residual is visible rather than silent. An identity that belongs to one
of these is treated as group-covered and is **not** given a direct grant — the two paths never both act on the
same identity — so if such a group is not brought into scope, its members remain part of that residual.

### Where it runs, and what each workspace needs

There is **one control workspace** — the workspace you deploy this bundle to. Every other workspace is a
**target**, reached only over HTTPS. Nothing is deployed to a target, and no table is ever created in one.

| | control workspace (×1) | target workspaces (×N) |
|---|---|---|
| bundle deployed | yes | **no** |
| compute runs | yes (the three jobs) | **no** |
| Unity Catalog required | **yes** — the inventory table and the seven output tables are Delta | **no** |
| catalog + schema needed | **yes**, as inputs (§6) | no |
| runner SP must be workspace admin | yes | **yes** — this is the only requirement |
| what the bundle does to it | writes its own tables inside your schema | reads; and `PATCH`es entitlements on in-scope groups |

So **a target workspace does not need Unity Catalog, a metastore, or any compute.** The audit tables are
created once, in the control workspace's catalog and schema. Whether a target is UC-enabled makes no
difference to any decision or any write — the entire target-side surface is two endpoints:

| endpoint | methods used |
|---|---|
| `/api/2.0/preview/access-control/entitlements-migration` | **`GET` only** — the bundle never opts a workspace in or out |
| `/api/2.0/preview/scim/v2/{Groups,Users,ServicePrincipals}` | `GET`, plus `PATCH` on in-scope group entitlements |

Neither is a Unity Catalog API.

**One control workspace per cloud.** A run takes a single `cloud` and a single runner credential, and the
inventory is filtered to that cloud — so an AWS estate and an Azure estate are two deployments and two runs,
each with its own control workspace and its own runner service principal.

---

## 2. Four jobs, run in order

| # | job | privilege | mutates | purpose |
|---|---|---|---|---|
| 0 | `entl_inventory` | **account admin** (once per cloud) | no by default | Enumerates the workspaces in scope from the account API, reports whether the runner is already a workspace admin on each, and writes `ws_inventory` — the input the other three read. Optionally grants the runner workspace admin, off by default. |
| 1 | `entl_audit` | workspace admin | **no** | Per workspace: migration state, every group with its entitlements and members, every principal, and which principals hold access only through `users`. |
| 2 | `entl_plan` | none (pure compute) | **no** | Turns the audit into one verdict per workspace and one action row per group. **This is the table to review and sign off.** |
| 3 | `entl_apply` | workspace admin | **yes, gated** | Executes only the rows the plan marked `GRANT`, re-reads each group to verify, and records before/after. |

Inventory, audit and plan are safe to run as often as you like. Nothing changes until `entl_apply` runs
with its confirmation token set.

**Why job 0 is separate.** It is the only job that needs account-level access, and it runs once per cloud.
Splitting it out is what lets jobs 1–3 run as an identity with **no account access at all** — the identity
doing the repeated work never holds account admin. See `DEPLOYMENT.md` for the two identities and how to
set them up.

---

## 3. Decision rules

### Per workspace — does it proceed?

Read the entitlements on `users`:

| `users` holds | verdict | reason code |
|---|---|---|
| both target entitlements (extras such as `workspace-consume` are fine) | **PROCEED** | — |
| `workspace-access` only | SKIP | `USERS_MISSING_SQL` |
| `databricks-sql-access` only | SKIP | `USERS_MISSING_WORKSPACE` |
| neither | SKIP | `USERS_MISSING_BOTH` |
| — workspace is already on the new behaviour | SKIP | `ALREADY_MIGRATED` |
| — the runner is not a workspace admin there | SKIP | `NOT_ADMIN` |

#### Already-migrated workspaces — `migrated_workspaces` (default `skip`)

After a workspace migrates, `users` holds nothing, so the rule above can never pass and the workspace is
skipped `ALREADY_MIGRATED`. That is the default and it is the safe answer. It also means that once the
change is enforced everywhere, this bundle has nothing left to do.

Set `migrated_workspaces=clone_fallback` and migrated workspaces are gated on the **migration clone group**
instead. This is not the rule being relaxed — the clone holds *exactly* what `users` held at the moment of
migration (a faithful copy, and no clone is created at all when there was nothing to copy), so the same
subset question is simply asked of the group that now carries the answer:

| migrated workspace, clone holds | verdict | reason code |
|---|---|---|
| both target entitlements | **PROCEED** | — |
| `workspace-access` only | SKIP | `CLONE_MISSING_SQL` |
| `databricks-sql-access` only | SKIP | `CLONE_MISSING_WORKSPACE` |
| neither (e.g. Consumer access only) | SKIP | `CLONE_MISSING_BOTH` |
| no clone group exists | SKIP | `NO_CLONE_GROUP` |
| the migration record names a clone that was not read | SKIP | `CLONE_GROUP_NOT_FOUND` |

`NO_CLONE_GROUP` and `CLONE_GROUP_NOT_FOUND` are deliberately separate. Both mean "no clone group was
read"; the discriminator is **whether the migration record names one**.

- **`NO_CLONE_GROUP`** — the record names no clone. A clone is a snapshot *of `users`*, and none is created
  when there was nothing to snapshot, so this says `users` was already empty at migration. Nobody lost
  anything and there is nothing to restore. Terminal and correct; **no action**. Granting here would confer
  entitlements nobody ever had, which is what the subset rule exists to prevent.
- **`CLONE_GROUP_NOT_FOUND`** — the record names a clone (say `users-clone-1757894400`) and the read did not
  return it: a projection dropped `entitlements`, a transient 5xx, eventual consistency, or the runner lost
  workspace admin so SCIM answered `200` with a reduced body. The platform is saying a snapshot **exists**
  and you failed to fetch it, so the subset question cannot be answered at all. **Investigate**: confirm the
  runner is a workspace admin, confirm the id resolves, re-read.

Absent id = the platform says there is nothing. Present id = the platform says there is something and your
read failed. Merged into one verdict, the second case would be filed as "nothing to restore" — a reassuring
reason — while that workspace's whole user population silently keeps no access. It is the same trap as absent
SCIM `entitlements` meaning EMPTY *only* if the projection was honoured: an unread thing and an empty thing
look identical unless you keep them apart on purpose.

Every verdict row records **`gate_source`** (`users` or `clone`) and **`gate_entitlements`**, so a report can
never hide which group a decision came from. The clone group itself is still **never modified** — it is
audited and read, exactly like the system groups.

`ALREADY_MIGRATED` and `NOT_ADMIN` are reported separately on purpose: both present as "`users` has no
entitlements" if you only look at the group list, and confusing them sends you chasing the wrong problem.

### Per group — is it in scope?

| `meta.resourceType` | `externalId` | classification | action |
|---|---|---|---|
| `Group` | populated (Entra objectId) | **AAD-synced account group** | **GRANT** |
| `Group` | empty | Databricks-native account group | audit only |
| `WorkspaceGroup` | — | legacy workspace-local group | audit only |
| `WorkspaceGroup` | — | `users`, `admins`, `users-clone-*` | never touched |

`aad_detection = external_id` (default) uses the table above. `aad_detection = all_account_groups` widens the
grant to every account group, for estates where the IdP does not populate `externalId`. **The report always
records which rule was applied.**

### Per grant — what actually happens

1. Read the group's current entitlements.
2. Compute only what is missing.
3. `PATCH … {"op":"add","path":"entitlements", …}` — the API **appends**; nothing existing is removed.
4. Re-read the group and verify the result is `previous ∪ targets`.
5. If any previously-present entitlement is missing after the write, **the whole run stops immediately**.

Already correct → recorded as `NOOP`, no call made. Re-running the bundle is safe and changes nothing.

---

## 4. Tables written

All in `<catalog>.<schema>`, appended, every row stamped with `run_id` and `run_ts`.

| table | one row per | key columns |
|---|---|---|
| `ws_inventory` | enumerated workspace | `workspace_id`, `workspace_name`, `host`, `cloud`, `account_id`, runner-admin readiness, `grant_status` — written by job 0 and read by the rest |
| `ws_migration_state` | workspace | `state`, `reason`, `disallow_users_group_entitlement_modification`, clone `group_id`, `entitlement_acl_paths`, `admin_ok` |
| `group_state` | group | `resource_type`, `external_id`, `classification`, `entitlements`, `member_count`, `is_system`, `is_clone` |
| `group_member` | group member | `member_id`, `member_type`, `member_display` |
| `principal_state` | user / service principal | `direct_entitlements`, `groups`, `effective_entitlements`, `access_only_via_users` |
| `ws_verdict` | workspace | `users_entitlements`, `verdict`, `reason`, group counts by classification |
| `group_action` | group | `action` (`GRANT`/`NOOP`/`OUT_OF_SCOPE`/`SKIP`), `reason` |
| `principal_action` | user / service principal | `principal_type`, `is_admin`, `reachable_groups`, `entitlements_before`, `missing`, `action`, `reason`, `direct_principals_mode` |
| `apply_outcome` | grant attempted | `entitlements_before`, `added`, `entitlements_after`, `status`, `verified`, `http_error` |

### What the non-obvious columns mean

`workspace_id`, `host`, `cloud`, `account_id`, `display_name` and the like are self-explanatory. These are not.

**`ws_migration_state`** — the platform's **own** record, read verbatim from
`GET /api/2.0/preview/access-control/entitlements-migration`. This bundle never writes it.

| column | what it is for |
|---|---|
| `admin_ok` | Derived from the probe, not from the record. `403` means identity B is **not** a workspace admin — and a non-admin SCIM read returns `200` with a *reduced* body, so such a workspace would look entitlement-free rather than erroring. `admin_ok=false` therefore excludes it from every conclusion. |
| `state` | `DISABLED` = still on legacy inheritance, so `users` still confers entitlements. `ENABLED` = already migrated, so `users` is empty and locked. `LEGACY_NO_RECORD` is **this bundle's own value, not the platform's**: the probe returned `200 {}`, meaning admin but *no migration record exists at all* — the workspace has never opted in or out. |
| `reason` | **How the state came to be, and the column most worth reading.** `CUSTOMER` = somebody made an explicit choice. `PHASE_2` = the automatic auto-enable wave did it. This is how you tell *"Databricks did this to me"* from *"we chose this"*. It is load-bearing because the wave only takes workspaces that made **no explicit choice**: `DISABLED` + `CUSTOMER` is a durable opt-out, while `LEGACY_NO_RECORD` (or `DISABLED` with no explicit reason) is *undecided* and can be taken at any time — including part-way through a run, which is why apply re-checks the gate live per workspace. |
| `initiator_principal_id`, `start_time`, `end_time` | Who triggered the migration and when it ran. `start_time` is how you date a migration that happened without you. |
| `clone_group_id` | The `users-clone-<TS>` group id **from the record**. Authoritative, and preferred over matching the `users-clone-*` name, because a group can be renamed. Empty means no clone was created — see §3. |
| `disallow_users_group_entitlement_modification` | The migration lock. When true, a PATCH to `users` or `admins` is refused `403`. The lock is **group-scoped, not principal-scoped**: writes to individual users and service principals are still permitted. |
| `entitlement_acl_paths` | Carried through from the record verbatim, unused by the logic. |
| `probe_error` | The error text when the probe failed, kept so a `NOT_ADMIN` workspace is diagnosable instead of silently skipped. |

**`ws_inventory`** — `grant_status` is `NOT_REQUESTED` unless `grant_runner_workspace_admin=true`, and
`runner_is_admin` is only populated when granting (it needs the **numeric** `runner_sp_principal_id`). With the
default settings the readiness signal you actually read is **`admins_present`** — the admin list per
workspace, which tells you whether identity B is among them.

**`group_state` / `group_action`** — `classification` is one of `aad_account_group`, `native_account_group`,
`workspace_local_group`, `system_group`, `migration_clone_group`, and it is what decides scope: only
`aad_account_group` is ever written to. `is_system` / `is_clone` are the never-modify flags.

**`principal_state`** — `access_only_via_users` is the population no group grant can reach, because `users` is
the only group it holds (see §7). `effective_entitlements` is the union of direct plus every group it inherits
through, which is why it can exceed `direct_entitlements`.

**`principal_action`** — one row per principal **considered**, in scope or not. `reachable_groups` lists the
groups a group grant could arrive through; `[]` means only `users`. `is_admin` is carved out explicitly:
admins are recorded as `SKIP` / `ADMIN_INHERITS_VIA_ADMINS_GROUP` rather than quietly omitted, so the table
**proves** they were considered and excluded rather than merely missed.

**`ws_verdict`** — `gate_source` (`users` or `clone`) and `gate_entitlements` record which group the decision
was actually taken from, so a report can never hide that a verdict came from a clone rather than `users`.

**`apply_outcome`** — `verified` is the result of an **independent re-read** after the write, not the HTTP
status: a `2xx` is not evidence that an entitlement is present. `added` is what this run actually appended
(`op:add` never removes), so `entitlements_before` + `added` should equal `entitlements_after`.

---

## 5. Safety gates

- **Fail-closed scoping.** A run must name its scope. Refuses outright unless at least one of
  `workspace_id_allowlist`, `workspace_name_pattern` or `allow_all_workspaces=true` is set. An empty
  allowlist never means "all". See the four selectors below.
- **Confirmation token.** `entl_apply` refuses to mutate unless `confirm_apply=GRANT-ENTITLEMENTS`.
- **Admin gate.** Each workspace is probed for admin rights before any group data is trusted. A non-admin
  read returns a *reduced* response with no error — groups appear to have no entitlements. Those workspaces
  are recorded `NOT_ADMIN` and excluded from every conclusion.
- **Explicit attributes.** All reads request their fields explicitly. A field absent from a response is
  treated as **unknown**, never as **empty**.
- **Per-workspace isolation.** One workspace failing never aborts the run; it becomes a row.
- **Verify-after-write** with a run-level circuit breaker (§3).

### Choosing how much of the estate a run touches

Four selectors. Combine them freely — **they intersect**, so adding one can only ever narrow the scope.

| parameter | effect |
|---|---|
| `workspace_id_allowlist` | comma-separated workspace ids. One workspace, or a hand-picked set |
| `workspace_name_pattern` | glob on `workspace_name` from the inventory, e.g. `prod-*` or `ws-eu-[0-9][0-9]` |
| `batch_size` + `batch_index` | split the selection into batches and run one. Ordering is by workspace id, so a given index always means the same workspaces |
| `allow_all_workspaces=true` | the whole inventory. Has to be set deliberately; it is never the default |

Plus one brake:

| parameter | effect |
|---|---|
| `max_workspaces` | if the selection exceeds this, the run **refuses**. It never truncates |

`max_workspaces` is deliberately not a filter. Silently processing the first N of a larger selection produces
a run that reports success while leaving the rest untouched, which is worse than not running — so the tool
stops and makes you choose. Deliberate partial coverage is what `batch_size`/`batch_index` are for, and they
announce themselves in the log (`batch 2 of 15`).

Every run prints the selectors it applied and the resulting count, e.g.:

```
scope: allowlist(2 ids) + name_pattern('prod-*') -> 1 of 1439 workspaces
```

**Recommended first run:** a narrow `workspace_name_pattern` or a short `workspace_id_allowlist`, with
`max_workspaces` set to what you expect. Widen only once the audit output looks right.

---

## 6. Prerequisites

Everything here is an **input you own and name**. [`prerequisites.sql`](prerequisites.sql) issues the
**grants** (item 2) and can optionally create the catalog and schema (item 1) if you want it to. The rest of
the list is yours to satisfy: item 3 is produced by job 0, and items 4 and 5 are account-level facts to
confirm before you start. `DEPLOYMENT.md` is the step-by-step version of this list.

1. **Catalog and schema — you create them, this bundle never does.** There is no `CREATE CATALOG` or
   `CREATE SCHEMA` anywhere in the code. You pass the names as the `catalog` and `schema` variables and the
   jobs create only their own tables inside the schema you named. Both are checked on startup, so a wrong
   name or a missing grant fails in seconds rather than after sweeping the fleet:

   ```
   preflight: schema entitlements_audit.bridge reachable (tables will be created inside it)
   ```

2. **Grants for the runner SP** on that catalog and schema:

   ```sql
   GRANT USE CATALOG                              ON CATALOG <catalog>          TO `<runner-sp-app-id>`;
   GRANT USE SCHEMA, CREATE TABLE, MODIFY, SELECT ON SCHEMA  <catalog>.<schema> TO `<runner-sp-app-id>`;
   ```

3. **Workspace inventory** — one row per target workspace (`cloud`, `workspace_id`, `host`) in
   `<catalog>.<schema>.ws_inventory`, or any table you point `inventory_table` at. Also an input: an account
   admin loads it once. This hand-off is deliberate — it is what lets the runner SP hold **no account-level
   access at all**.

4. **Runner service principal** with **workspace admin** on every target workspace, and its OAuth
   client id/secret in a secret scope (`secret_scope`, `runner_client_id_key`, `runner_client_secret_key`).

5. Premium plan or above (entitlements are a Premium feature).

Nothing else is assumed. Every path, name and identifier the jobs touch comes from a variable — see the
`variables:` block in `databricks.yml`.

---

## 6a. Reporting

[`reports.sql`](reports.sql) has the five read-only queries to hand back after a run: pre-change
entitlements per group per workspace, the skipped-workspace list with reasons, the before → after audit
trail, the principals a group grant cannot reach, and a one-line fleet summary.

Because every table is append-only and stamped with `run_id`/`run_ts`, running `entl_audit` again after
`entl_apply` gives a true before/after: the earlier run is the "before" and is never overwritten.

---

## 7. Behaviours this design depends on — all verified by test, not assumption

1. **Inheritance is per principal, not per group.** A service principal whose only group is `users`, holding
   no access entitlement of its own, could call the workspace, SQL and cluster APIs. Once that inheritance
   was gone it received `403 "This API is disabled for users without the workspace-access entitlement."`
2. **Standalone principals are not reachable by group grants.** A user or service principal assigned to a
   workspace with no group membership gets nothing from this bundle. They are preserved by the
   `users-clone-<timestamp>` group Databricks creates during migration — which is why this bundle never
   touches `users`.
3. **No entitlements on `users` ⇒ no clone group at all.** Verified: with `users` emptied first, migration
   completed and created **no** clone group of any name, and the migration record carried no clone id. The
   API accepts a clone name and silently ignores it. **Do not clear entitlements from `users` before the
   enforcement date.**
4. **Entitlements on account groups are workspace-scoped.** The same account group granted in workspace A
   showed no change in workspace B or at account level. There is no account-level shortcut; every workspace
   must be visited.
5. **A workspace admin can grant on an account group** — no account admin required for the grant itself.
6. **`op:add` appends and is idempotent.** Verified against a group holding an unrelated entitlement: it
   survived untouched, and re-adding an existing entitlement produced neither an error nor a duplicate.
7. **Entitlements on a principal's record are direct grants only.** Effective access must be computed as
   `direct ∪ (⋃ entitlements of every group the principal belongs to)`. The API's `groups` attribute is
   already flattened across nested groups, and nested membership does confer the parent's entitlements.
8. **The rate limiter is per workspace.** One workspace saturated at 8 concurrent writes returned 62 rate
   limit rejections against 8 successes, while another workspace wrote cleanly at full speed in the same
   moment. Hence: parallel across workspaces, strictly serial within one. ~0.7–0.8 writes/s per workspace.
9. **Revocation does not affect tokens already issued** (OAuth tokens live 3600s). Failures appear **later**,
   not at the moment of change, so an uneventful first hour proves nothing (see §9).
10. **Reduced responses look like empty ones.** A non-admin group read, and the account-level group list,
    both silently omit fields. Hence the admin gate and explicit-attribute rules in §5.
11. **A no-op write on a locked system group returns success.** Only a write that would actually change
    something returns 403 — so response codes are never taken as proof; every write is verified by re-reading.

---

## 8. Throughput

Serial within a workspace, parallel across workspaces. With ~0.7 writes/s per workspace:

| groups per workspace | 700 workspaces | 8 in flight | 16 in flight |
|---|---|---|---|
| 20 | 14,000 writes | ~40 min | ~20 min |
| 50 | 35,000 writes | ~1.6 h | ~50 min |
| 250 | 175,000 writes | ~8 h | ~4 h |

Rate limits recover on their own; the runner backs off and resumes rather than abandoning a workspace.

---

## 9. Limits — read this before relying on the bundle

- **This is a one-time bridge.** The grants are point-in-time. If your IaC manages entitlements, declare
  these two entitlements there — otherwise your next apply reverts them.
- **`migrated_workspaces=clone_fallback` changes who is in scope.** With it on, workspaces that have already
  moved to the new behaviour are acted on rather than skipped. Two consequences worth deciding deliberately
  before switching it on: the clone group is a **one-time snapshot that is never reconciled**, so granting to
  your account groups is what keeps *future* joiners working — and equally, it restores automatic inheritance
  for future members of those groups, which the new behaviour is designed to make explicit. Whether that is
  what you want is a policy question, not a technical one.
- **Standalone principals are out of reach** (§7.2). The audit lists them in
  `principal_state.access_only_via_users` so they can be handled deliberately.
- **Skipped workspaces need a human.** They are reported with a reason, not silently passed over.
- **Failures after the cutover are delayed.** Expect them over hours, as tokens and cached sessions refresh.
  Monitor well beyond the event itself.
- **Workspaces created before the enforcement date are still born on the legacy behaviour**, so any workspace
  added between an audit and the deadline needs the same treatment. Re-run the audit close to the date.

---

## 10. Running it

```bash
databricks bundle validate -t validate -p <PROFILE>
databricks bundle deploy   -t validate -p <PROFILE>

databricks bundle run entl_audit -t validate -p <PROFILE>   # read-only
databricks bundle run entl_plan  -t validate -p <PROFILE>    # review ws_verdict + group_action
databricks bundle run entl_apply -t validate -p <PROFILE>    # gated; token must be set
```

`-t validate` runs a small allowlist first. `-t rollout` runs the whole account once the validate wave's
plan and outcome tables look right.

Set the two targets' `host` and variables in `databricks.yml` before the first deploy — they ship with
placeholders. One deploy per Databricks account, with `cloud` set to match it.

### Operational notes

Four things that will otherwise cost you an afternoon:

- **`bundle run` looks hung long after the job has finished.** It streams logs until the run is reaped. Use
  `--no-wait`, take the run id from the URL it prints, and poll `databricks jobs get-run <id>`. Each job's
  counts come back as JSON in the run output, so `get-run-output` is enough to see what happened.
- **`--var` splits on commas**, so `--var="workspace_id_allowlist=111,222"` fails with
  `unexpected flag value for variable assignment: 222`. Keep the allowlist in the target's `variables:`
  block in `databricks.yml`, which is where it belongs anyway — it is the scope of a rollout wave.
- **CLI commands run from inside the bundle directory pick up the default target's host.** Unrelated
  commands then fail with a confusing auth error against the wrong workspace. Run other CLI work from
  outside this directory, or pass `-p <PROFILE>` explicitly.
- **`allow_all_workspaces=true` is the only way to run without an allowlist.** An empty allowlist is
  refused, never interpreted as "all".

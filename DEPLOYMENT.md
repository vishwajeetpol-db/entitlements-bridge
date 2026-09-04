# Entitlements Bridge — Deployment Guide

A step-by-step guide to deploying and running the entitlements bridge in your Databricks account.
Work through the sections in order. Nothing changes an entitlement until **section 8**.

`README.md` explains the design and the reasoning; this document is the procedure.

---

## Quick reference

The whole procedure, once you have read it through. Nothing changes an entitlement until the last command.

```bash
# one-time setup
#   - identity A: account-admin service principal        (job 0 only)
#   - identity B: runner SP, workspace admin on targets  (jobs 1-3 only, no account access)
#   - run prerequisites.sql sections 1 and 2 on a SQL warehouse
#   - create the secret scope with the four keys
#   - edit databricks.yml: workspace host, account_admin_run_as, and the variables in section 4

databricks bundle validate -t <target>
databricks bundle deploy   -t <target>
# then grant identity A CAN_READ on the bundle root, or use a shared root_path (section 3.4)

# dry run - no entitlement changes
databricks bundle run entl_inventory -t <target>
databricks bundle run entl_audit     -t <target>
databricks bundle run entl_plan      -t <target>

# REVIEW: ws_verdict, group_action, principal_action. action='GRANT' is exactly what will change.

# the only command that changes anything
databricks bundle run entl_apply -t <target> -- --confirm_apply GRANT-ENTITLEMENTS
```

| stage | section | changes entitlements? | roughly |
|---|---|---|---|
| prerequisites and identities | 2 | no | one-time |
| deploy | 3 | no | minutes |
| configure parameters | 4 | no | one-time per target |
| pre-flight checklist | 5 | no | minutes |
| dry run, jobs 0-2 | 6 | **no** | about a minute per job at pilot scale |
| review | 7 | no | as long as it takes |
| apply, job 3 | 8 | **yes** | scales with the number of grants |

Job 2 prints its own estimate for the apply, based on the grants it planned and your
`workspaces_in_flight` setting. Use that rather than extrapolating from a pilot.

---

## 1. What this tool does

Databricks is changing how workspace entitlements are controlled. After the change:

- the **`users`** system group holds **no entitlements**, and its entitlements are **locked**;
- the **`admins`** system group holds **all** workspace entitlements, also locked;
- entitlements that were on `users` are copied into a workspace-local clone group named
  `users-clone-<TIMESTAMP>`, so principals that already existed keep their access.

Historically every principal added to a workspace inherited `Workspace access` and `Databricks SQL access`
from `users`. Once `users` is empty, nothing inherits them — so entitlements have to live somewhere that
survives. This tool puts them there, before the change reaches your workspaces.

### What it grants

Two entitlements, and only these two:

| entitlement | API value | what it allows |
|---|---|---|
| Workspace access | `workspace-access` | sign in to the workspace |
| Databricks SQL access | `databricks-sql-access` | use Databricks SQL in that workspace |

It grants them **only in workspaces where the `users` group still holds both today**, to two populations:

1. **IdP-backed account groups** — identified by the presence of an `externalId`, never by name.
2. **Identities no group grant can reach** — a non-admin user or service principal whose only group is
   `users`. Without this they would inherit nothing once `users` is emptied. Controlled by
   `direct_principals`; set it to `skip` to restrict the run to groups alone.

### What it never does

- never modifies `users`, `admins`, or a migration clone group;
- never modifies workspace-local groups, or account groups without an `externalId` — both are reported as
  out of scope rather than silently ignored;
- **never writes to an admin.** Membership of `admins` already carries all five workspace entitlements
  (`workspace-consume`, `workspace-access`, `databricks-sql-access`, `allow-cluster-create`,
  `allow-instance-pool-create`), so an admin needs nothing from this tool. Admins still appear in the
  report, marked `ADMIN_INHERITS_VIA_ADMINS_GROUP`, so you can see they were considered;
- never removes an entitlement — it only ever appends;
- never creates or drops a catalog or schema;
- never changes group membership.

With `direct_principals=skip` it writes to no individual identity at all. With the default `grant` it adds
the two entitlements directly to the non-admin, group-less identities described above.

### The four jobs

| job | what it does | changes entitlements? |
|---|---|---|
| `0 · inventory` | lists the workspaces in scope | no |
| `1 · audit` | reads groups, principals and migration state | no |
| `2 · plan` | computes a verdict per workspace and an action per group and principal | no |
| `3 · apply` | executes only the `GRANT` rows from the plan | **yes — gated** |

Jobs 0–2 are safe to run as often as you like. Job 3 refuses to run without an explicit confirmation token.

---

## 2. Before you start

### 2.1 Two identities, and they are deliberately separate

| | identity | needs | used by |
|---|---|---|---|
| **A** | account-admin service principal | **account admin** on the Databricks account | job 0 **only** |
| **B** | runner service principal | **workspace admin** on every target workspace. **No account access.** | jobs 1, 2, 3 **only** |

This split is the point, not an inconvenience:

- **A never touches a workspace.** It makes two read calls to list workspaces, once per account, and writes
  the result to a table. It is not used again.
- **B never has account access.** It cannot enumerate your account and cannot see workspaces outside the
  scope you name. Everything that reads or writes entitlements runs as B.

Use B's **`applicationId`** (a UUID) wherever a client id is required — not its numeric SCIM id. A numeric id
produces `invalid_client` at token time.

Identity A may be a **user** instead of a service principal if you intend to run job 0 by hand; see
`account_admin_run_as` in section 4. A scheduled run needs a service principal.

### 2.2 One governance workspace

Pick one workspace to deploy into. It holds the jobs and the output tables. Every other workspace is a
**target**, reached only over HTTPS — nothing is deployed to a target, and no table is created in one.

The governance workspace must be **Unity Catalog enabled**, and needs a **SQL warehouse** you can run
`prerequisites.sql` on.

### 2.3 Destination catalog and schema

Create them, or choose existing ones. The tool never creates or drops either.

**Create the catalog and schema yourself first.** `prerequisites.sql` section 1 creates nothing — it is
commented out on purpose, and offers three `CREATE CATALOG` forms because which one works depends on your
metastore. Check `storage_root` first (`GET /api/2.1/unity-catalog/metastore_summary`): if it is set, the
bare `CREATE CATALOG` works; if it is `NULL`, a bare create fails and you need Default Storage via the UI
or an explicit `MANAGED LOCATION`. Section 1 documents all three.

Then run `prerequisites.sql` **section 2** on your SQL warehouse. It grants, to **both** identities:

- `USE CATALOG` on the catalog;
- `USE SCHEMA`, `CREATE TABLE`, `MODIFY`, `SELECT` on the schema.

Both identities need the catalog grant. A missing `USE CATALOG` does not fail at start — it surfaces
mid-run as `[UNAUTHORIZED_ACCESS] … does not have USE CATALOG`.

### 2.4 A secret scope holding both identities' credentials

Create a scope in the governance workspace with four keys:

| key | value |
|---|---|
| `runner_client_id` | identity B `applicationId` |
| `runner_client_secret` | identity B OAuth secret |
| `account_client_id` | identity A `applicationId` |
| `account_client_secret` | identity A OAuth secret |

> **Recommended:** put identity A's credentials in a **separate scope** from identity B's, and grant each
> identity `READ` on only its own. Identity A is an account admin over your whole estate; anyone who can
> read that scope holds it. The key names are configurable (section 4) precisely so the two can be split.

### 2.5 Four bindings the UC grants do not cover

Because job 0 runs as a different identity from jobs 1–3, four things are needed beyond the grants. Each
fails with a distinct error, listed so you can recognise it.

| | requirement | error if missing |
|---|---|---|
| **a** | Both identities must **exist in the governance workspace**. Workspace `USER` is enough — the jobs are serverless, so no compute entitlement is needed. | deploy: `400 INVALID_PARAMETER_VALUE — Invalid user: '<appId>' does not exist or deactivated` |
| **b** | The identity that runs `bundle deploy` needs `roles/servicePrincipal.user` **on identity A**, or the jobs API will not let it bind A as a `run_as`. | deploy: `403 PERMISSION_DENIED — Cannot bind the service principal provided in 'run_as' field` |
| **c** | Identity A needs **`READ` on the secret scope** holding its own credentials. | job 0 cannot obtain an account token |
| **d** | Identity A needs to **read the deployed bundle files**. A bundle deploys under the *deploying* identity's workspace home, so a job running as a different identity cannot see its own notebook. | job 0: `RESOURCE_NOT_FOUND — Unable to access the notebook` |

> The account rule-set API behind **(b)** is eventually consistent. If you grant the role and immediately
> read it back it can appear missing when it has in fact applied. Re-read before concluding it failed.

**How to grant (b).** The rule-set API needs a read-modify-write with an `etag`; a plain write is rejected
with `400 INVALID_PARAMETER_VALUE — Missing required field: rule_set.etag`. You must also **carry over the
existing `grant_rules`**, or you will revoke whoever currently holds `servicePrincipal.manager`.

```bash
ACCT=<databricks-account-id>
A=<identity-A-applicationId>          # the SP being granted ON
B=<deploying-identity-applicationId>  # the SP that runs `bundle deploy`
NAME="accounts/$ACCT/servicePrincipals/$A/ruleSets/default"

# 1. read the current rule set and keep its etag
databricks api get \
  "/api/2.0/preview/accounts/$ACCT/access-control/rule-sets?name=$NAME&etag=" > current.json

# 2. write it back with your rule appended, including the etag from step 1
#    (edit current.json: keep every existing entry in grant_rules and add the one below)
#      {"principals": ["servicePrincipals/$B"], "role": "roles/servicePrincipal.user"}
databricks api put "/api/2.0/preview/accounts/$ACCT/access-control/rule-sets" --json @updated.json
```

If `bundle deploy` still fails with `Cannot bind the service principal provided in 'run_as' field`, re-read
before retrying — see the consistency note above.

### 2.6 Workspace admin on every target

Identity B must be a **workspace admin** on each target workspace. A non-admin SCIM read returns HTTP 200
with a reduced response, so a non-admin workspace would look entitlement-free rather than erroring. The tool
detects this and records such workspaces as `NOT_ADMIN`, excluding them from every conclusion — but they are
then skipped, so fix the admin grant before trusting a run.

Job 0 reports which targets are missing the admin grant, without changing anything.

---

## 3. Deploy the bundle

### 3.1 Install and authenticate

```bash
databricks --version    # any version with bundle support; validated on v1.6.0
databricks auth login --host https://<governance-workspace-host>
```

### 3.2 Replace the two placeholders the bundle ships with

Both are in `databricks.yml`. Neither can be supplied on the command line.

| where | ships as | replace with |
|---|---|---|
| `targets.<target>.workspace.host` | `https://<governance-workspace-host>` | your governance workspace URL |
| `account_admin_run_as.service_principal_name` | `<account-admin-sp-application-id>` | identity A's `applicationId` |

The second one **passes `bundle validate` and fails `bundle deploy`**, and the error quotes the placeholder
rather than the variable name:

```
Error: cannot create resources.jobs.entl_inventory:
'<account-admin-sp-application-id>' cannot be set as run_as service principal,
because it doesn't exist. (400 INVALID_PARAMETER_VALUE)
```

`account_admin_run_as` is a **complex** variable. It must **replace** the whole mapping, not merge into it —
a merge leaves both `service_principal_name` and `user_name` present and the jobs API rejects the result with
the same 400. `--var` cannot set it either; the CLI rejects a JSON value for a complex variable. **Editing
`databricks.yml` is the only way.**

```yaml
# a scheduled run — identity A is a service principal
variables:
  account_admin_run_as:
    service_principal_name: "<identity-A-applicationId>"

# a hands-on run — identity A is a human account admin
variables:
  account_admin_run_as:
    user_name: "someone@example.com"
```

### 3.3 Validate, then deploy

```bash
databricks bundle validate -t <target>
databricks bundle deploy   -t <target>
```

Confirm every job resolved to exactly **one** `run_as` key before deploying:

```bash
databricks bundle validate -t <target> -o json | jq '.resources.jobs[].run_as'
```

### 3.4 Give identity A access to the bundle files

This is binding **(d)** from section 2.5: a bundle deploys under the *deploying* identity's workspace home,
so a job whose `run_as` is a different identity cannot see its own notebook.

**Do this.** After the first deploy, grant identity A `CAN_READ` on the bundle root that `bundle deploy`
printed. The root stays private to the deploying identity, and only identity A is added to it.

**The shared-root alternative, and why it does not lead here.** A shared root also fixes (d) permanently:

```yaml
targets:
  <target>:
    workspace:
      host: https://<governance-workspace-host>
      root_path: /Shared/.bundle/${bundle.name}/${bundle.target}
```

…but both `bundle validate` and `bundle deploy` then warn, and on this bundle the warning is material:

```
Warning: the bundle root path /Workspace/Shared/.bundle/<name>/<target>
is writable by all workspace users
```

Identity A is an **account admin over your whole estate**, and job 0 executes its notebook from that root. A
bundle root every workspace user can write is therefore a route for any of them to alter code that then runs
with account-admin authority. Prefer the `CAN_READ` grant above. Use a shared root only if that folder is
restricted by other means, and if you accept it, add `CAN_MANAGE` for `group_name: users` deliberately so the
choice is visible in the config rather than implied by a warning nobody read.

---

## 4. Configure the parameters

Set these in your target's `variables:` block in `databricks.yml`. Everything not listed has a working
default. The jobs read them as task parameters — you do not edit anything inside the job definitions.

### 4.1 Required

| variable | set to |
|---|---|
| `cloud` | `aws` or `azure` — **one account per deploy**. This derives the account host, so a mismatch here fails job 0 |
| `account_id` | your Databricks account id |
| `runner_sp_application_id` | identity B `applicationId` |
| `account_admin_run_as` | identity A — see section 3.2 |
| `catalog` / `schema` | the destination from section 2.3, which must already exist |
| `secret_scope` | the scope from section 2.4 |

`cloud`, `account_id` and the credentials in the secret scope must all belong to the **same** account. If
they do not, job 0 fails at the account-token step and the error names all three so you can compare them.

### 4.2 Scope — you must name one, and an empty allowlist never means "all"

The run **refuses to start** unless the scope is named one of three ways.

| variable | example value | use |
|---|---|---|
| `workspace_id_allowlist` | `"1234567890123456,2345678901234567"` | comma-separated workspace ids — best for a first pilot |
| `workspace_name_pattern` | `"prod-*"` &nbsp;or&nbsp; `"emea-prod-*"` | glob on workspace name — best for rollout |
| `allow_all_workspaces` | `"true"` | only for a deliberate whole-account run |

**Which jobs enforce it.** Jobs **0, 1 and 3** each apply the scope independently — so the same value belongs
on all three. **Job 2 (plan) has no scope of its own:** it plans exactly the set job 1 audited. To change what
gets planned, change job 1's scope and re-run job 1. §4.5 covers what that means for a staged ramp.

**Set exactly one.** Selectors **intersect**: with both an allowlist and a pattern, a workspace must satisfy
both, so a stale id in the allowlist silently shrinks the selection. Two guards refuse rather than continue:

- an unresolved `<placeholder>` left in any scope selector, in `catalog` / `schema` / `secret_scope`, or in
  `inventory_table`;
- a scoped run that matches **0 of N** workspaces — a scoped run selecting nothing is a configuration
  mistake, not an empty estate.

### 4.3 Safety and throughput

| variable | default | meaning |
|---|---|---|
| `max_workspaces` | `0` (off) | ceiling. If the scope selects more, the run **refuses** rather than processing a prefix — a truncated run that reports success is worse than no run |
| `batch_size` / `batch_index` | `0` / `0` | deliberate partial coverage, 0-based. Selection order is stable, so an index always means the same workspaces |
| `workspaces_in_flight` | `8` | workspaces processed concurrently. Work is serial *within* a workspace by design |
| `confirm_apply` | `""` | job 3 refuses unless this is exactly `GRANT-ENTITLEMENTS`. **Leave it empty here** and pass it per run (section 8), or the gate stops being a gate |

### 4.4 Behaviour

| variable | default | change it when |
|---|---|---|
| `direct_principals` | `grant` | set `skip` to entitle account groups only and write to no individual identity. At `grant`, non-admin users and service principals whose only group is `users` are entitled directly — without it those identities inherit nothing after the change. Admins are excluded in both modes |
| `aad_detection` | `external_id` | your IdP does not populate `externalId` on account groups. `all_account_groups` widens the target set — confirm that wider set is what you want first |
| `migrated_workspaces` | `skip` | you want already-migrated workspaces acted on, gated on the clone group instead of `users`. This makes the tool act on workspaces it would otherwise decline |
| `grant_runner_workspace_admin` | `false` | you want job 0 to also make identity B a workspace admin where it is not one. Requires `runner_sp_principal_id` (the **numeric** id). Left `false`, job 0 makes no changes at all |
| `capture_members` | `true` | set `false` to omit group-membership rows from the audit |
| `output` / `out_dir` | `delta` / `./out` | `json` writes newline-delimited JSON instead of Unity Catalog tables |
| `runner_client_id_key`, `runner_client_secret_key`, `account_client_id_key`, `account_client_secret_key` | conventional names | your keys are named differently, or identity A's credentials live in a separate scope |
| `inventory_table` | `<catalog>.<schema>.ws_inventory` | the inventory should live elsewhere |

### 4.5 Changing how many workspaces a run covers — without redeploying

The values in `databricks.yml` are the **defaults baked in at deploy time**. Every job also declares a
run-time parameter for each setting in this section, so any of them can be changed for a single run.

| route | how | use for |
|---|---|---|
| Jobs UI | open the job → **▾ → Run now with different settings** → edit the value | a one-off canary or pilot |
| CLI | `databricks bundle run entl_audit -t <target> -- --workspace_id_allowlist "<id1>,<id2>"` | scripted ramps |
| Redeploy | edit `databricks.yml`, then `databricks bundle deploy` | making the new value permanent |

`--var=` on the command line splits on commas, so a multi-id allowlist must go through the UI, the `--`
form above, or the YAML.

**A typical ramp.** Job 0 can stay wide throughout — it is two read calls and builds the full inventory once.

| stage | set on jobs 1 and 3 | covers |
|---|---|---|
| canary | `workspace_id_allowlist = "1234567890123456"` | 1 |
| pilot | `workspace_id_allowlist = "1234567890123456,2345678901234567,3456789012345678"` … ten ids in total | 10 |
| rollout | keep `workspace_name_pattern = "prod-*"`, add `batch_size = 50`, then step `batch_index` `0`, `1`, `2` … | 50 per run |
| whole estate | `workspace_name_pattern = "*"`, or `allow_all_workspaces = "true"` | all |

Worked example, one wave of the rollout stage:

```bash
# wave 1 of a prod-* estate, 50 workspaces at a time
databricks bundle run entl_audit -t rollout -- \
  --workspace_name_pattern "prod-*" --batch_size 50 --batch_index 0
databricks bundle run entl_plan  -t rollout                      # no scope of its own
databricks bundle run entl_apply -t rollout -- \
  --workspace_name_pattern "prod-*" --batch_size 50 --batch_index 0 \
  --confirm_apply GRANT-ENTITLEMENTS
# wave 2 is the same three commands with --batch_index 1
```

Scope is enforced on **jobs 0, 1 and 3**, and jobs 1 and 3 must be given the **same** values — `batch_size`
and `batch_index` included. Two consequences worth knowing before you plan a ramp:

- **Job 2 (plan) has no scope of its own.** It plans exactly the set job 1 audited. To change what gets
  planned, change job 1's scope and re-run job 1.
- **Job 3 (apply) can only narrow, never widen.** It builds its work list from the plan's grant rows and then
  applies the scope to *that*, so it can never reach a workspace the plan did not cover — and a scope mismatch
  between job 1 and job 3 shows up as fewer grants than the plan listed, not as an error. Auditing and
  planning the whole estate, reviewing it, then applying to ten workspaces is a supported sequence.

Selectors **intersect** (4.2), and this matters most at run time: an allowlist supplied in the Run-now
dialog is ANDed with any `workspace_name_pattern` still set from the deploy. An id outside that pattern
selects nothing, and the run refuses rather than reporting a successful no-op.

---

## 5. Pre-flight checklist

Work down this list before running anything. Each item has a distinct failure mode if skipped.

| ✓ | check | how |
|---|---|---|
| ☐ | identity A is an **account admin** | account console → the SP's Roles |
| ☐ | identity B is a **workspace admin** on every target | job 0 will report any that are not |
| ☐ | both identities exist in the **governance workspace** | Settings → Identity and access |
| ☐ | the deploying identity has `servicePrincipal.user` **on identity A** | section 2.5(b) |
| ☐ | catalog and schema **exist** — you create these, the tool never does | §2.3; `prerequisites.sql` §1 documents three ways but is commented out |
| ☐ | both identities hold `USE CATALOG` **and** the four schema privileges | `prerequisites.sql` §2, then `SHOW GRANTS` |
| ☐ | the secret scope holds **all four keys** | `databricks secrets list-secrets <scope>` |
| ☐ | identity A has **`READ`** on that scope | section 2.5(c) |
| ☐ | identity A can **read the bundle files** | section 3.4 |
| ☐ | a **SQL warehouse** is available and running | for `prerequisites.sql` and `reports.sql` |
| ☐ | `cloud`, `account_id` and the scope credentials are the **same account** | section 4.1 |
| ☐ | **exactly one** scope selector is set | section 4.2 |
| ☐ | every job resolved to **one** `run_as` key | `bundle validate -o json \| jq '.resources.jobs[].run_as'` |
| ☐ | `confirm_apply` is **empty** in `databricks.yml` | section 4.3 |

---

## 6. Dry run — jobs 0, 1 and 2

These three make **no entitlement or permission changes**. They read your estate and write tables.

```bash
databricks bundle run entl_inventory -t <target>   # identity A: which workspaces are in scope
databricks bundle run entl_audit     -t <target>   # identity B: groups, principals, migration state
databricks bundle run entl_plan      -t <target>   # verdicts and per-object actions
```

**Run them back to back — no pause needed.** `bundle run` blocks until the job reaches a terminal state,
so each one has finished before the next begins. It can *look* like it has hung while a serverless job
starts; that is the wait, not a stall.

🔴 **The exception: if you use `--no-wait`, you must wait for each job yourself.** `--no-wait` returns a run
id immediately instead of blocking, and these three are a chain — job 1 reads the table job 0 writes, and
job 2 reads job 1's tables. Starting the next one early gives you a job that reads a missing or stale table
rather than a clear error. Poll each run to a terminal state before starting the next:

```bash
databricks bundle run entl_inventory -t <target> --no-wait   # prints a run id
databricks jobs get-run <run-id> -o json | jq -r '.state.life_cycle_state, .state.result_state'
# wait for  TERMINATED  and  SUCCESS  -- then start entl_audit
```

Check **both** fields. `TERMINATED` only means the run stopped; a failed run is also `TERMINATED`, with
`result_state = FAILED`. Poll on the terminal state alone and you will start the next job after a failure.

There is no propagation delay to allow for between the jobs: the output tables are Delta, so once a job
reports success its rows are committed and the next job sees them.

### Running the jobs from the workspace UI instead of the CLI

You do not have to use `bundle run`. After `bundle deploy` these are four ordinary jobs in your governance
workspace, and **Run now** works normally. Measured, not assumed:

| in the UI | what happens |
|---|---|
| **Run now** on jobs 0, 1, 2 | runs exactly as the CLI does — every setting is stored on the job |
| **Run now** on job 3 (apply) | **refuses and changes nothing**: `refusing to mutate: set confirm_apply=GRANT-ENTITLEMENTS once the plan has been reviewed.` |
| **Run now with different settings** on job 3, with `confirm_apply` filled in | applies the plan |

🔴 **This is the safety property, not an inconvenience.** The plain **Run now** button on job 3 cannot change
an entitlement, because `confirm_apply` is stored empty on the job (section 4.3). The token must be typed in
by hand every time — the same deliberate act as passing it after `--` on the command line. Keep it empty in
`databricks.yml`.

#### Running the apply from the UI — step by step

1. **Workflows → Jobs**, open the job whose name ends **`3 · apply (gated, mutates)`**.
2. Click the **▾** next to the **Run now** button and choose **Run now with different settings**.
3. The `apply` task is already selected — the dialog shows **1 of 1 selected**. Leave that alone.
4. On the right is the full parameter list, alphabetical, each pre-filled from your deployment. Find
   **`confirm_apply`** — it sits between `cloud` and `direct_principals`, and it is the **one row whose
   value box is empty**.
5. **Type exactly this value:**

   ```
   GRANT-ENTITLEMENTS
   ```

   **Upper case, with a hyphen, and no quotes.** The comparison is exact, so `grant-entitlements` and
   `GRANT_ENTITLEMENTS` are both refused and nothing is changed. Leading and trailing spaces *are* trimmed,
   so an accidental space either side is harmless — but do not rely on that, and do not add quotes.
6. **Change nothing else in that dialog.** The other values are what job 2 planned against. Editing
   `catalog`, `schema`, `mode` or a scope field here means you would be applying something you never
   reviewed. (Narrowing scope deliberately is a supported thing to do — see section 4.5 — but do it as its
   own decision, not while typing the confirmation token.)
7. Click **Run**.

**The value is not remembered, by design.** It applies to that single run only: the job still stores
`confirm_apply` as empty afterwards, and the run records it as an override. So every apply from the UI
requires the token to be typed again, and nobody can leave the gate propped open for the next person.

> If you see **Switch to legacy parameters** in that dialog, ignore it. The list described above is the
> current form and is what these jobs expect.

Two practical notes:

- **Who can press it.** The deploying identity owns the jobs and the workspace `admins` group gets
  `CAN_MANAGE`, so any workspace admin in the governance workspace can run them from the UI. Anyone else
  needs `CAN_RUN` granting explicitly on each job.
- **Order still matters.** The UI gives you no sequencing: it is on you to let job 0 finish before starting
  job 1, and job 1 before job 2, for the same reason as the `--no-wait` case above.

Any run is also safe to repeat. Re-running job 3 after a successful apply reports every object as `NOOP`
rather than granting anything twice.

### Confirm the tables were created in your catalog and schema

After all three have run, eight tables should exist in `<catalog>.<schema>`:

```sql
SHOW TABLES IN <catalog>.<schema>;
```

| table | written by | what to look at |
|---|---|---|
| `ws_inventory` | job 0 | one row per workspace in scope — check this count against what you expected |
| `ws_migration_state` | job 1 | migration state per workspace, and whether identity B is admin there |
| `group_state` | job 1 | every group, its classification and its entitlements |
| `group_member` | job 1 | group membership (omit with `capture_members=false`) |
| `principal_state` | job 1 | every user and service principal, direct **and** effective entitlements, `is_admin` |
| **`ws_verdict`** | job 2 | **PROCEED or SKIP per workspace, and why** — start here |
| **`group_action`** | job 2 | **the action decided for each group** |
| **`principal_action`** | job 2 | **the action decided for each identity**, including the admin exclusions |
| **`apply_outcome`** | job 3 | what was actually written: before, added, after, and `verified` |

`apply_outcome` appears only after job 3 — eight tables before the apply, nine after. All nine are
append-only and stamped with `run_id` + `run_ts`, so re-running a job adds a generation rather than
overwriting one, and "latest" always means `max(run_ts)`.

If a table is missing, the job that writes it did not complete — check that run rather than continuing.

---

## 7. Review the dry run before you change anything

This is the review gate. Everything job 3 will do is already written down in `ws_verdict`,
`group_action` and `principal_action`. Nothing else will happen.

### Which query to run, and when

`reports.sql` ships the full SQL; run it on your SQL warehouse with `:catalog` and `:schema` replaced.
There are **three** moments worth querying — not four. Before the dry run no tables exist yet, and "after
the dry run" and "before the apply" are the same moment.

| phase | when | run |
|---|---|---|
| **1 · readiness** | before any job | no tables exist yet. Use the checklist in §5, plus `SHOW GRANTS` on your catalog and schema and a check that the secret scope holds its four keys |
| **2 · review** | after jobs 0–2, **before** the apply | report **5** fleet summary → report **2** skipped workspaces → report **7** what will change → report **1** pre-change state → report **4** identities no group can reach |
| **3 · verification** | after the apply | report **7** again (now carrying the outcome) → report **3** before→after per group → report **6** per-identity decision + outcome → report **5** again, to compare against phase 2 |

**Report 7 is the one to hand a change board.** One row per object — groups and identities together — with
what it held, what will be or was added, and whether the write was confirmed by re-read. Before the apply
its outcome columns are `NULL`; after, they carry the result. `planned_action = 'GRANT'` is the exact and
complete set of objects the apply touches.

The three quick checks below are inline so you can paste them without opening the file:

### 7.1 Are the right workspaces in scope?

```sql
SELECT count(*) AS in_scope FROM <catalog>.<schema>.ws_inventory
WHERE run_ts = (SELECT max(run_ts) FROM <catalog>.<schema>.ws_inventory);
```

Compare this against the number you expect from your scope selector. If it is 0 the run would have refused;
if it is larger than expected, tighten the selector before proceeding.

### 7.2 What is the verdict per workspace, and why?

```sql
SELECT workspace_name, verdict, reason, gate_source, gate_entitlements,
       groups_to_grant, principals_to_grant, principals_admin_excluded
FROM <catalog>.<schema>.ws_verdict
WHERE run_ts = (SELECT max(run_ts) FROM <catalog>.<schema>.ws_verdict)
ORDER BY verdict, workspace_name;
```

| verdict / reason | meaning |
|---|---|
| `PROCEED` | `users` holds both entitlements — this workspace will be changed |
| `SKIP` `USERS_MISSING_SQL` / `USERS_MISSING_WORKSPACE` / `USERS_MISSING_BOTH` | `users` does not hold both today, so granting them would be **new access, not a bridge** |
| `SKIP` `ALREADY_MIGRATED` | the change has already reached this workspace |
| `SKIP` `NOT_ADMIN` | identity B is not a workspace admin — nothing read here can be trusted |
| `SKIP` `USERS_GROUP_NOT_FOUND` / `WORKSPACE_READ_FAILED` | the read did not return what it needs; investigate rather than re-run |

`gate_source` and `gate_entitlements` record **which group the decision was read from and what it held**, so
a verdict is never a bare assertion.

### 7.3 What will be changed, object by object?

```sql
-- groups
SELECT workspace_id, display_name, classification, entitlements_before, missing, action, reason
FROM <catalog>.<schema>.group_action
WHERE run_ts = (SELECT max(run_ts) FROM <catalog>.<schema>.group_action)
ORDER BY action, workspace_id;

-- identities
SELECT workspace_id, principal_type, identifier, is_admin, reachable_groups,
       entitlements_before, missing, action, reason
FROM <catalog>.<schema>.principal_action
WHERE run_ts = (SELECT max(run_ts) FROM <catalog>.<schema>.principal_action)
ORDER BY action, workspace_id;
```

**`action = GRANT` is the complete list of what job 3 will change.** Everything else is a record of what was
considered and left alone:

| action / reason | meaning |
|---|---|
| `GRANT` | `missing` will be added. Nothing existing is removed |
| `NOOP` `ALREADY_HAS_BOTH` | already correct |
| `SKIP` `SYSTEM_GROUP_NEVER_MODIFIED` | `users` or `admins` |
| `SKIP` `DATABRICKS_MANAGED_CLONE` | a `users-clone-*` group |
| `OUT_OF_SCOPE` `NOT_AAD_ACCOUNT_GROUP` / `LEGACY_WORKSPACE_LOCAL_GROUP` | no `externalId`, or workspace-local. **Members of these keep nothing unless the group is brought into scope** — review this list |
| `SKIP` `ADMIN_INHERITS_VIA_ADMINS_GROUP` | an admin. Never written to |
| `SKIP` `COVERED_BY_GROUP_GRANT` | the identity is in a group that is being granted |
| `SKIP` `PRINCIPAL_INACTIVE` | a deactivated identity |
| `SKIP` `WORKSPACE_SKIPPED:<reason>` | the workspace itself was skipped — see 7.2 |

Sign off on these three queries before continuing. Re-running jobs 1 and 2 after any change to your estate
is free.

---

## 8. The actual run

```bash
databricks bundle run entl_apply -t <target> -- --confirm_apply GRANT-ENTITLEMENTS
```

The token is passed **per run**, after the `--`. It is not set in `databricks.yml`.

**Running it from the workspace UI instead?** The same gate applies and the plain **Run now** button will
refuse. Use **▾ → Run now with different settings** and set `confirm_apply` to `GRANT-ENTITLEMENTS`; the
click-by-click steps, including which of the twenty fields to edit and which to leave alone, are in
section 6 under *Running the apply from the UI*.

Job 3 executes only the `GRANT` rows from the plan you just reviewed, and holds three properties:

1. **The gate is re-checked live.** A plan can be hours old. Before touching a workspace the job re-reads
   the migration state and the `users` entitlements and abandons that workspace if the gate no longer holds.
   Each identity's scope is re-checked the same way, so an identity promoted to admin since the plan was
   written is abandoned rather than written to.
2. **Verify after write.** A no-op PATCH on a locked object returns success, so a 2xx proves nothing. Every
   object is re-read and must contain `before ∪ targets`.
3. **Circuit breaker.** If a pre-existing entitlement ever disappears, the whole run aborts. One workspace
   behaving differently stops the run rather than corrupting the rest.

Re-running job 3 is safe: it grants only what is still missing.

### Verify against your estate, not the job summary

```bash
# groups
databricks api get "/api/2.0/preview/scim/v2/Groups?attributes=id,displayName,entitlements,externalId,meta" -p <profile>
# identities — both collections, because job 3 can write to either
databricks api get "/api/2.0/preview/scim/v2/Users?attributes=id,userName,active,entitlements,groups" -p <profile>
databricks api get "/api/2.0/preview/scim/v2/ServicePrincipals?attributes=id,applicationId,active,entitlements,groups" -p <profile>
```

Confirm the intended account groups now hold both entitlements; that groups on skipped workspaces are
unchanged; and that `users`, `admins`, clone groups, workspace-local groups and account groups without an
`externalId` are all untouched.

For identities, confirm those marked `GRANT` now hold both, and that **everything else is unchanged from the
pre-run audit** — not merely that it "lacks the two entitlements". An admin may already hold them directly
for unrelated reasons, so "does not have them" is the wrong test and produces false alarms. `reports.sql`
report 6 puts the decision and the outcome side by side.

> `meta` is deliberately absent from the two identity queries: SCIM returns it for a Group but not for a
> User or ServicePrincipal. Asking for it and not receiving it is expected, not a failed read.

### Rollback and reversibility

Be clear about this before you seek approval, because there is no undo button.

| | reversible? |
|---|---|
| An entitlement this tool **added** | **Not automatically.** The tool only ever appends and has no remove path. Reverse it yourself in Settings → Identity and access, or with a SCIM `remove` operation on the object |
| A workspace the tool **skipped** | nothing to reverse — it was not touched |
| Deploying the bundle | `databricks bundle destroy -t <target>` removes the jobs. It does not touch entitlements |
| The output tables | plain Delta tables in your catalog. Drop them if you want; they are append-only history, not state the tool depends on |

Two things make this safer than it sounds:

- **`GRANT` in the plan is the exact and complete list.** Nothing outside it is written, so the blast radius
  is knowable before you run and auditable afterwards from `apply_outcome`.
- **The grants restore inherited access rather than create new access.** A workspace is only eligible when
  `users` still holds both entitlements — meaning every principal there already has them by inheritance
  today. The tool moves that access somewhere that survives the migration. Where `users` does **not** hold
  both, the workspace is skipped precisely because granting would be new access.

If you need a reversal plan for change control: `apply_outcome` lists every object written, with
`entitlements_before` and `added`, which is exactly what a revert needs.

### `apply_outcome`

```sql
SELECT workspace_id, target_type, display_name, identifier, status,
       entitlements_before, added, entitlements_after, verified, http_error
FROM <catalog>.<schema>.apply_outcome
WHERE run_ts = (SELECT max(run_ts) FROM <catalog>.<schema>.apply_outcome)
ORDER BY status, workspace_id;
```

| status | meaning |
|---|---|
| `GRANTED` | written and confirmed by re-read |
| `NOOP` | already correct |
| `ABANDONED_*` | the live re-check no longer held — nothing written. The suffix says which check |
| `FAILED_PRECHECK` | the object could not be read reliably, so it was not written |
| `FAILED` / `FAILED_UNVERIFIED` | the write failed, or could not be confirmed. `http_error` carries the reason |
| `FAILED_ENTITLEMENT_LOSS` | the circuit breaker fired. Investigate before re-running |

---

### 🔴 Tell your users: a grant does not take effect on a session that is already open

**This is the most likely support ticket you will get after a successful run.** A user or service principal
that was signed in *before* the grant will keep being refused, and the API message makes it look as though
nothing was granted at all:

```
This API is disabled for users without the databricks-sql-access or workspace-consume entitlements.
```

Measured behaviour: after a grant that was confirmed by an independent SCIM re-read, the same identity was
still refused for **around ten minutes** across repeated attempts — including with a token obtained through
the CLI's **refresh** flow (`databricks auth token`). A full re-login (`databricks auth login`) then
succeeded immediately.

**So:** ask affected users to **sign out and sign back in**. Do not conclude the grant failed. Verify the
grant with the SCIM re-read above — if the entitlement is present there, the grant *did* work and the
session is stale.

The API error text names the entitlements it requires, which makes triage quick:

| endpoint | message names |
|---|---|
| `/api/2.0/preview/scim/v2/Me` | `databricks-sql-access` **or** `workspace-access` **or** `workspace-consume` |
| `/api/2.0/sql/statements` | `databricks-sql-access` **or** `workspace-consume` |

### After the cutoff date, adding a principal to a workspace grants entitlements directly

Once a workspace has migrated, adding a principal to it assigns entitlements **on that principal** rather
than relying on inheritance from `users` — that is the point of the change. Worth knowing because it means
your onboarding process, not group membership, becomes the place entitlements are decided.

## 9. Appendix

### 9.1 Jobs, notebooks and identities

| job | notebook | runs as | reads | writes | mutates |
|---|---|---|---|---|---|
| `entl_inventory` | `src/entl_inventory.py` | **identity A** (account admin) | account workspace list | `ws_inventory` | no |
| `entl_audit` | `src/entl_audit.py` | identity B | migration state, groups, members, principals per workspace | `ws_migration_state`, `group_state`, `group_member`, `principal_state` | no |
| `entl_plan` | `src/entl_plan.py` | identity B | the audit tables | `ws_verdict`, `group_action`, `principal_action` | no |
| `entl_apply` | `src/entl_apply.py` | identity B | `group_action`, `principal_action`, live re-check | `apply_outcome` | **yes, gated** |

Shared logic lives in `src/entl_common.py`: configuration, the workspace and account sessions, the scope
guard, the workspace gate and the per-identity decision. The gate and the decision each exist in exactly one
place, so job 2 and job 3 cannot drift apart — job 3's live re-check asks a byte-identical question.

### 9.2 Files

| file | purpose |
|---|---|
| `databricks.yml` | the bundle: four jobs and every variable |
| `prerequisites.sql` | catalog, schema and grants for both identities |
| `reports.sql` | seven hand-back queries, indexed by phase (readiness / review / verification) |
| `src/` | the four job notebooks plus shared logic |
| `README.md` | the design and the reasoning |

### 9.3 Troubleshooting

| symptom | cause | fix |
|---|---|---|
| `invalid_client` at token time | the numeric SCIM id was used as a client id | use the `applicationId` |
| `Secret does not exist with scope: … key: account_client_id` | the key is absent, or identity A lacks `READ` | section 2.4, then 2.5(c). This is a secret-access error, not evidence about the identity's type |
| deploy `400 … Invalid user: '<appId>' does not exist or deactivated` | the SP is not a member of the governance workspace | section 2.5(a) |
| `validate`/`deploy`: `default auth: cannot configure default credentials … host=https://<governance-workspace-host>` | **the host placeholder was never replaced.** This surfaces as an *authentication* error, not a placeholder error, so it is easy to spend time on credentials that are fine | section 3.2. Replace `targets.<target>.workspace.host` first, before anything else |
| deploy `403 … Cannot bind the service principal provided in 'run_as' field` | the deploying identity lacks `servicePrincipal.user` on identity A | section 2.5(b) |
| deploy `400 … cannot be set as run_as service principal` | `account_admin_run_as` still holds the placeholder, or was merged instead of replaced | section 3.2 |
| `RESOURCE_NOT_FOUND — Unable to access the notebook` | job 0's identity cannot read the deployed bundle | section 3.4 |
| `This API is disabled for users without the databricks-sql-access …` **after** a successful run | the user's session predates the grant | not a failure. Confirm the entitlement is present via the SCIM re-read in section 8, then have the user **sign out and back in**. Allow ~10 minutes |
| `account token request failed: HTTP 400` in job 0 | `cloud`, `account_id` and the scope credentials do not all belong to the same account — most often `cloud` left at its default on the other cloud's account | the error prints the endpoint, the derived account host and the account id. Make all three agree |
| `[UNAUTHORIZED_ACCESS] … does not have USE CATALOG` mid-run | the catalog-level grant is missing | section 2.3 |
| `[INVALID_STATE] Metastore storage root URL does not exist` when creating the catalog | your metastore has no storage root | read the rest of that error, which names both remedies. With Default Storage, create the catalog in Catalog Explorer and pick it. Otherwise create it with an explicit `MANAGED LOCATION` on an external location you own |
| `refusing to run: name the scope with …` | no scope selector set | section 4.2 |
| `refusing to run: these scope settings still hold the placeholder values …` | a `<placeholder>` was never replaced | section 4.2. Set the real value, or `""` if you scope another way |
| `refusing to run: the scope selected 0 of N workspaces` | selectors intersected to nothing, usually an allowlist ANDed with a pattern | section 4.2. Use exactly one selector |
| `refusing to run: catalog='<catalog>' still holds the placeholder value` | `catalog`, `schema` or `secret_scope` not replaced | section 4.1 |
| `refusing to run: … above the max_workspaces ceiling` | the selection exceeds `max_workspaces` | narrow the scope, raise the ceiling, or use `batch_size` |
| `refusing to mutate: set confirm_apply=GRANT-ENTITLEMENTS` | job 3 run without the token | intended. Review the plan, then pass the token after `--` |
| job 3 reports fewer workspaces than the plan | the gate was re-checked live and some workspaces changed | compare `ws_verdict` with `apply_outcome`, then re-run jobs 1–2 |
| run halted mid-apply | the circuit breaker saw a pre-existing entitlement disappear | intended. Investigate before re-running — something outside this tool changed the estate |

### 9.4 Groups are classified by type, never by name

Classification uses `meta.resourceType` and `externalId`, not the display name. On a real estate names
mislead in both directions: a group named like an IdP group that is in fact workspace-local with manually
managed membership, and a genuine IdP-backed account group whose name carries no such prefix. A
name-matching approach grants to the first — reaching none of the members it appears to reach, and reporting
success — and misses the second entirely.

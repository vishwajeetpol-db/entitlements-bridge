# Databricks notebook source
# MAGIC %md
# MAGIC # Task 0 of 4 — inventory (ACCOUNT ADMIN, run once per cloud)
# MAGIC
# MAGIC This is the **only** task that needs account-level access, and the only one that talks to the account
# MAGIC console API. It enumerates the workspaces in scope and writes the `ws_inventory` table that tasks
# MAGIC 1–3 read. After it has run, everything else works with a service principal that is **workspace admin
# MAGIC only** and holds no account rights at all.
# MAGIC
# MAGIC That hand-off is the whole point of splitting it out: the powerful identity is used once, briefly,
# MAGIC and its output is a table.
# MAGIC
# MAGIC **It changes nothing by default.** With `grant_runner_workspace_admin=false` (the default) this task
# MAGIC is read-only against the account: it lists workspaces, reports whether the runner SP is *already* a
# MAGIC workspace admin on each, and writes its own table. Set the flag to `true` only if you want it to also
# MAGIC grant that permission.
# MAGIC
# MAGIC **Scope is fail-closed.** It refuses to run without `workspace_id_allowlist`,
# MAGIC `workspace_name_pattern`, or an explicit `allow_all_workspaces=true` — because an account can hold
# MAGIC thousands of workspaces, most of them nothing to do with this exercise.

# COMMAND ----------

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)) if "__file__" in dir() else os.getcwd())

import entl_common as C  # noqa: E402

# COMMAND ----------

conf = C.load_conf()
C.banner(conf, "ENTITLEMENTS BRIDGE — 0/4 INVENTORY (account admin)")
writer = C.Writer(conf)
account = C.AccountSession(conf)

if conf.grant_runner_workspace_admin and not conf.runner_sp_principal_id:
    raise SystemExit(
        "grant_runner_workspace_admin=true needs runner_sp_principal_id — the NUMERIC account id of the "
        "runner service principal (not its applicationId UUID)."
    )
print(f"account {conf.account_id} via {conf.account_host}")
print(f"grant_runner_workspace_admin={conf.grant_runner_workspace_admin}"
      + (f" (runner principal {conf.runner_sp_principal_id})" if conf.grant_runner_workspace_admin else ""))

# COMMAND ----------

raw, err = account.list_workspaces()
if err:
    raise SystemExit(f"cannot list workspaces in account {conf.account_id}: {err}")
print(f"account holds {len(raw)} workspaces")

candidates = [
    {
        "workspace_id": str(w.get("workspace_id")),
        "workspace_name": w.get("workspace_name"),
        "host": C.workspace_host_of(w),
        "workspace_status": w.get("workspace_status"),
        "pricing_tier": w.get("pricing_tier"),
        "region": w.get("aws_region") or w.get("location"),
    }
    for w in raw
]

# THE guard. Applied to the enumeration itself, before a single per-workspace call is made.
scoped = C.enforce_scope(conf, candidates)
if not scoped:
    print("nothing in scope — no rows written")

# COMMAND ----------


def inspect(row: dict) -> dict:
    """Read the workspace's permission assignments; grant ADMIN only when explicitly asked to."""
    ws_id = str(row["workspace_id"])
    out = dict(row)
    out.update(
        cloud=conf.cloud,
        account_id=conf.account_id,
        runner_sp_principal_id=conf.runner_sp_principal_id or None,
        runner_is_admin=None,
        grant_status="NOT_REQUESTED",
        http_error=None,
    )
    if not row.get("host"):
        out["grant_status"] = "SKIPPED_NO_HOST"
        return out
    if str(row.get("workspace_status")) not in ("RUNNING", "None", "", "null") and row.get("workspace_status"):
        if str(row["workspace_status"]) != "RUNNING":
            out["grant_status"] = f"SKIPPED_STATUS_{row['workspace_status']}"
            return out

    assignments, aerr = account.permission_assignments(ws_id)
    if aerr:
        out["http_error"] = aerr
        out["grant_status"] = "READ_FAILED"
        return out
    if conf.runner_sp_principal_id:
        out["runner_is_admin"] = any(
            str((pa.get("principal") or {}).get("principal_id")) == str(conf.runner_sp_principal_id)
            and "ADMIN" in (pa.get("permissions") or [])
            for pa in assignments
        )
    out["admins_present"] = sorted(
        str((pa.get("principal") or {}).get("display_name"))
        for pa in assignments if "ADMIN" in (pa.get("permissions") or [])
    )

    if conf.grant_runner_workspace_admin:
        if out["runner_is_admin"]:
            out["grant_status"] = "ALREADY_ADMIN"
        else:
            gerr = account.grant_workspace_admin(ws_id, conf.runner_sp_principal_id)
            out["grant_status"] = "GRANTED" if not gerr else "GRANT_FAILED"
            out["http_error"] = gerr
            if not gerr:
                out["runner_is_admin"] = True
    return out


rows = C.fan_out(scoped, inspect, conf.workspaces_in_flight) if scoped else []

# COMMAND ----------

writer.write("ws_inventory", rows)

usable = [r for r in rows if r.get("host") and str(r.get("workspace_status") or "RUNNING") == "RUNNING"]
missing_admin = [r for r in usable if r.get("runner_is_admin") is False]
by_grant: dict[str, int] = {}
for r in rows:
    by_grant[str(r.get("grant_status"))] = by_grant.get(str(r.get("grant_status")), 0) + 1

print("-" * 78)
print(f"inventory rows written: {len(rows)} | usable (RUNNING, host known): {len(usable)}")
print(f"grant status: {by_grant}")
if conf.runner_sp_principal_id:
    print(f"runner SP is already workspace admin on {len(usable) - len(missing_admin)} of {len(usable)}")
    if missing_admin:
        print(f"  !! {len(missing_admin)} workspace(s) where the runner SP is NOT admin — tasks 1-3 will")
        print(f"     record them NOT_ADMIN and exclude them. Grant it there, or re-run this task with")
        print(f"     grant_runner_workspace_admin=true.")
        for r in missing_admin[:15]:
            print(f"       {r['workspace_id']}  {r.get('workspace_name')}")
else:
    print("runner_sp_principal_id not set — admin readiness not assessed")
print("\nhand-off complete: tasks 1-3 read this table and need no account access.")
C.emit_summary({
    "task": "inventory",
    "run_id": conf.run_id,
    "account_id": conf.account_id,
    "workspaces_in_account": len(raw),
    "in_scope": len(scoped),
    "rows": len(rows),
    "usable": len(usable),
    "runner_missing_admin": len(missing_admin),
    "grant_status": by_grant,
    "granted_admin": conf.grant_runner_workspace_admin,
})

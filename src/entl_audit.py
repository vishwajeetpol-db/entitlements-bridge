# Databricks notebook source
# MAGIC %md
# MAGIC # Task 1 of 3 — audit (READ ONLY)
# MAGIC
# MAGIC Per workspace, records what is actually there today: the migration state, every group with its
# MAGIC entitlements and members, every principal, and which principals hold their access **only** through
# MAGIC the `users` system group.
# MAGIC
# MAGIC This task never writes to a workspace. It is safe to run as often as you like.
# MAGIC
# MAGIC Two guards matter here and are not optional:
# MAGIC   * **admin gate** — a non-admin SCIM read returns `id`+`displayName` with HTTP 200 and no error, so
# MAGIC     every group would look entitlement-free. Workspaces where the runner is not an admin are recorded
# MAGIC     `NOT_ADMIN` and excluded from every conclusion.
# MAGIC   * **explicit attributes** — a field missing from a response means UNKNOWN, never EMPTY.

# COMMAND ----------

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)) if "__file__" in dir() else os.getcwd())

import entl_common as C  # noqa: E402

# COMMAND ----------

conf = C.load_conf()
C.banner(conf, "ENTITLEMENTS BRIDGE — 1/3 AUDIT (read only)")
writer = C.Writer(conf)
client_id, client_secret = C.resolve_runner_credentials(conf)
inventory = C.enforce_scope(conf, C.read_inventory(conf, writer))

# COMMAND ----------


def audit_workspace(row: dict) -> dict:
    """Everything for one workspace, strictly sequential (the rate limiter is per workspace)."""
    ws_id = str(row["workspace_id"])
    host = str(row["host"])
    session = C.WorkspaceSession(host, client_id, client_secret, ws_id)
    out: dict = {
        "workspace_id": ws_id,
        "host": host,
        "cloud": conf.cloud,
        "ws_migration_state": [],
        "group_state": [],
        "group_member": [],
        "principal_state": [],
    }

    record, admin_ok, err = session.admin_probe()
    state_row = {
        "workspace_id": ws_id,
        "host": host,
        "cloud": conf.cloud,
        "admin_ok": admin_ok,
        "probe_error": err,
        "state": (record or {}).get("state") if record else ("LEGACY_NO_RECORD" if admin_ok else None),
        "reason": (record or {}).get("reason") if record else None,
        "initiator_principal_id": (record or {}).get("initiator_principal_id") if record else None,
        "start_time": (record or {}).get("start_time") if record else None,
        "end_time": (record or {}).get("end_time") if record else None,
        "clone_group_id": (record or {}).get("group_id") if record else None,
        "entitlement_acl_paths": (record or {}).get("entitlement_acl_paths") if record else None,
        "disallow_users_group_entitlement_modification": (
            (record or {}).get("disallow_users_group_entitlement_modification") if record else None
        ),
    }
    out["ws_migration_state"].append(state_row)
    if not admin_ok:
        print(f"  {ws_id} NOT_ADMIN — excluded from all conclusions ({(err or '')[:90]})")
        return out

    groups, gerr = session.scim_pages("Groups", C.GROUP_ATTRS if conf.capture_members else C.GROUP_ATTRS_LIGHT)
    if gerr:
        state_row["probe_error"] = gerr
        print(f"  {ws_id} group read failed: {gerr[:120]}")
        return out

    group_entitlements: dict[str, list[str]] = {}
    for group in groups:
        name = str(group.get("displayName") or "")
        ents = C.entitlements_of(group)
        group_entitlements[name] = ents
        classification = C.classify_group(group, conf.aad_detection, state_row.get("clone_group_id"))
        out["group_state"].append(
            {
                "workspace_id": ws_id,
                "group_id": str(group.get("id")),
                "display_name": name,
                "resource_type": C.resource_type(group),
                "external_id": group.get("externalId"),
                "external_id_is_entra_guid": C.looks_like_entra_object_id(group.get("externalId")),
                "classification": classification,
                "entitlements": ents,
                "read_trustworthy": C.read_trustworthy(group),
                "member_count": len(group.get("members") or []),
                "is_system": classification == C.CLS_SYSTEM,
                "is_clone": classification == C.CLS_CLONE,
                "has_workspace_access": "workspace-access" in ents,
                "has_sql_access": "databricks-sql-access" in ents,
                # doc-mandated pre-migration check: a system group nested inside another group
                "nests_system_group": any(
                    str(m.get("display")) in C.SYSTEM_GROUPS for m in (group.get("members") or [])
                ),
            }
        )
        if conf.capture_members:
            for member in group.get("members") or []:
                out["group_member"].append(
                    {
                        "workspace_id": ws_id,
                        "group_id": str(group.get("id")),
                        "group_display_name": name,
                        "member_id": str(member.get("value")),
                        "member_display": member.get("display"),
                        "member_type": str(member.get("$ref") or "").split("/")[0] or None,
                    }
                )

    for resource, attrs, kind in (("Users", C.USER_ATTRS, "user"), ("ServicePrincipals", C.SP_ATTRS, "service_principal")):
        principals, perr = session.scim_pages(resource, attrs)
        if perr:
            print(f"  {ws_id} {resource} read failed: {perr[:110]}")
            continue
        for principal in principals:
            group_names = C.group_names_of(principal)
            direct = C.entitlements_of(principal)
            effective = C.effective_entitlements(principal, group_entitlements)
            non_users_groups = [g for g in group_names if g != "users"]
            out["principal_state"].append(
                {
                    "workspace_id": ws_id,
                    "principal_type": kind,
                    "principal_id": str(principal.get("id")),
                    "identifier": principal.get("userName") or principal.get("applicationId"),
                    "display_name": principal.get("displayName"),
                    "active": principal.get("active"),
                    "direct_entitlements": direct,
                    "groups": group_names,
                    "effective_entitlements": effective,
                    "has_effective_workspace_access": "workspace-access" in effective,
                    "has_effective_sql_access": "databricks-sql-access" in effective,
                    # admin membership, recorded explicitly. Admins inherit all five workspace entitlements via
                    # `admins` and are never written to; relying on them merely "holding some group" would
                    # break the day the scope predicate changes.
                    "is_admin": C.is_admin_principal(group_names),
                    # groups a group grant can actually flow through (excludes `users` and `admins`)
                    "reachable_groups": C.reachable_group_names(group_names),
                    # was the `entitlements` projection honoured? absent + no meta means UNKNOWN, not EMPTY
                    "entitlements_trustworthy": C.principal_read_trustworthy(principal),
                    # the population group grants cannot reach
                    "access_only_via_users": (not non_users_groups)
                    and not ({"workspace-access", "databricks-sql-access"} & set(direct)),
                }
            )

    stand_alone = sum(1 for p in out["principal_state"] if p["access_only_via_users"])
    admins = sum(1 for p in out["principal_state"] if p["is_admin"])
    ungrouped = sum(1 for p in out["principal_state"]
                    if not p["is_admin"] and not p["reachable_groups"])
    by_class: dict[str, int] = {}
    for g in out["group_state"]:
        by_class[g["classification"]] = by_class.get(g["classification"], 0) + 1
    print(
        f"  {ws_id} ok | state={state_row['state']} reason={state_row['reason']} | "
        f"groups={len(out['group_state'])} {by_class} | principals={len(out['principal_state'])} "
        f"| access_only_via_users={stand_alone} | admins={admins} ungrouped_non_admin={ungrouped} "
        f"| throttles={session.throttle_events}"
    )
    return out


# COMMAND ----------

results = C.fan_out(inventory, audit_workspace, conf.workspaces_in_flight)

for table in ("ws_migration_state", "group_state", "group_member", "principal_state"):
    rows: list[dict] = []
    for result in results:
        rows.extend(result.get(table, []))
    writer.write(table, rows)

not_admin = [r for r in results if not (r["ws_migration_state"] or [{}])[0].get("admin_ok")]
print("-" * 78)
print(f"audited {len(results)} workspaces | NOT_ADMIN {len(not_admin)}")
if not_admin:
    print("  NOT_ADMIN workspaces (fix the admin grant before trusting any verdict for these):")
    for r in not_admin[:25]:
        print(f"    {r['workspace_id']}  {r['host']}")
print(f"row counts: {writer.counts}")
C.emit_summary({
    "task": "audit",
    "run_id": conf.run_id,
    "workspaces_audited": len(results),
    "workspaces_not_admin": len(not_admin),
    "rows": writer.counts,
})

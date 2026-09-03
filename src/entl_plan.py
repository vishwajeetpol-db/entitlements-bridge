# Databricks notebook source
# MAGIC %md
# MAGIC # Task 2 of 3 — plan (PURE COMPUTE, no API calls)
# MAGIC
# MAGIC Turns the audit into decisions. Writes one verdict row per workspace, one action row per group, and
# MAGIC one action row per principal. **This is the output to review and sign off before anything mutates.**
# MAGIC
# MAGIC Two populations, deliberately separate:
# MAGIC   * `group_action` — AAD account groups. Unchanged.
# MAGIC   * `principal_action` — every principal, with the reason it is in or out of scope. In scope means
# MAGIC     non-admin, active, and holding no group but `users`, so no group grant can reach it. Admins are
# MAGIC     recorded as `SKIP/ADMIN_INHERITS_VIA_ADMINS_GROUP` rather than silently omitted, so the report
# MAGIC     proves they were considered and excluded.
# MAGIC
# MAGIC Workspace gate (subset rule): proceed when `users` holds **both** target entitlements. Extras such as
# MAGIC `workspace-consume` do not block. Skip when either is missing — and say which.
# MAGIC
# MAGIC `ALREADY_MIGRATED` and `NOT_ADMIN` are separate reasons on purpose: both look exactly like
# MAGIC "`users` has no entitlements" if you only read the group list.

# COMMAND ----------

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)) if "__file__" in dir() else os.getcwd())

import entl_common as C  # noqa: E402

# COMMAND ----------

conf = C.load_conf()
C.banner(conf, "ENTITLEMENTS BRIDGE — 2/3 PLAN (no changes)")
writer = C.Writer(conf)

states = writer.read("ws_migration_state")
groups = writer.read("group_state")
principals = writer.read("principal_state")
# workspace_name is needed on every verdict row so that apply can re-scope with the SAME
# enforce_scope() call. ws_migration_state may not carry it, so fall back to the inventory task 0 wrote.
inv_names = {str(r.get("workspace_id")): str(r.get("workspace_name") or "")
             for r in (writer.read("ws_inventory") or [])}

# newest run only, so a re-planned fleet never mixes generations
if states:
    latest = max(str(s.get("run_id")) for s in sorted(states, key=lambda s: str(s.get("run_ts"))))
    latest_ts = max(str(s.get("run_ts")) for s in states)
    keep_run = [s for s in states if str(s.get("run_ts")) == latest_ts]
    run_ids = {str(s.get("run_id")) for s in keep_run}
    states = keep_run
    groups = [g for g in groups if str(g.get("run_id")) in run_ids]
    principals = [p for p in principals if str(p.get("run_id")) in run_ids]
    print(f"planning against audit run(s) {sorted(run_ids)} at {latest_ts}")
print(f"input: {len(states)} workspaces, {len(groups)} groups, {len(principals)} principals")

# COMMAND ----------


as_list = C.as_list  # one definition, shared with apply


groups_by_ws: dict[str, list[dict]] = {}
for g in groups:
    groups_by_ws.setdefault(str(g.get("workspace_id")), []).append(g)

principals_by_ws: dict[str, list[dict]] = {}
for p in principals:
    principals_by_ws.setdefault(str(p.get("workspace_id")), []).append(p)

TARGETS = set(C.TARGET_ENTITLEMENTS)
verdict_rows: list[dict] = []
action_rows: list[dict] = []
principal_rows: list[dict] = []

for state in states:
    ws_id = str(state.get("workspace_id"))
    ws_groups = groups_by_ws.get(ws_id, [])
    users_group = next((g for g in ws_groups if str(g.get("display_name")) == "users"), None)
    users_ents = set(as_list((users_group or {}).get("entitlements")))

    # The clone group only carries a decision in clone_fallback mode. Resolve it by the id the migration
    # record reported; fall back to the audit's own classification, which already applied that id and then
    # the default name prefix.
    clone_gid = state.get("clone_group_id")
    clone_row = None
    if clone_gid:
        clone_row = next((g for g in ws_groups if str(g.get("group_id")) == str(clone_gid)), None)
    if clone_row is None:
        clone_row = next((g for g in ws_groups if str(g.get("classification")) == C.CLS_CLONE), None)

    gate = C.gate_workspace(
        admin_ok=bool(state.get("admin_ok")),
        migration_state=state.get("state"),
        users=C.group_ents_from_row(users_group),
        clone=C.group_ents_from_row(clone_row),
        clone_group_id=clone_gid,
        migrated_workspaces=conf.migrated_workspaces,
    )
    verdict, reason = gate.verdict, gate.reason

    by_class: dict[str, int] = {}
    grant_count = noop_count = 0
    for g in ws_groups:
        classification = str(g.get("classification"))
        by_class[classification] = by_class.get(classification, 0) + 1
        ents = set(as_list(g.get("entitlements")))
        missing = sorted(TARGETS - ents)

        if classification == C.CLS_SYSTEM:
            action, arsn = "SKIP", "SYSTEM_GROUP_NEVER_MODIFIED"
        elif classification == C.CLS_CLONE:
            action, arsn = "SKIP", "DATABRICKS_MANAGED_CLONE"
        elif classification in (C.CLS_NATIVE, C.CLS_LOCAL):
            action, arsn = "OUT_OF_SCOPE", (
                "NOT_AAD_ACCOUNT_GROUP" if classification == C.CLS_NATIVE else "LEGACY_WORKSPACE_LOCAL_GROUP"
            )
        elif verdict != C.V_PROCEED:
            action, arsn = "SKIP", f"WORKSPACE_SKIPPED:{reason}"
        elif not missing:
            action, arsn = "NOOP", "ALREADY_HAS_BOTH"
            noop_count += 1
        else:
            action, arsn = "GRANT", None
            grant_count += 1

        action_rows.append(
            {
                "workspace_id": ws_id,
                "host": state.get("host"),
                "group_id": str(g.get("group_id")),
                "display_name": g.get("display_name"),
                "classification": classification,
                "external_id": g.get("external_id"),
                "entitlements_before": sorted(ents),
                "missing": missing,
                "action": action,
                "reason": arsn,
                "aad_detection": conf.aad_detection,
            }
        )

    # ---- per-principal decisions (path 2): identities no group grant can reach --------------------
    # Path 1 (AAD account groups, above) is unchanged. This adds the identities it cannot serve: a
    # non-admin user or SP whose only group is `users`. Admins are excluded here, not merely absent.
    ws_principals = principals_by_ws.get(ws_id, [])
    p_grant = p_noop = p_admin = p_skip = 0
    for pr in ws_principals:
        trust = pr.get("entitlements_trustworthy")
        if trust is None:
            pplan = C.PrincipalPlan(C.PA_SKIP, C.PR_STALE_AUDIT, [])
        else:
            pplan = C.plan_principal(
                group_names=as_list(pr.get("groups")),
                direct_entitlements=as_list(pr.get("direct_entitlements")),
                entitlements_trustworthy=bool(trust),
                active=pr.get("active"),
                ws_verdict=verdict,
                ws_reason=reason,
                direct_principals=conf.direct_principals,
            )
        if pplan.action == C.PA_GRANT:
            p_grant += 1
        elif pplan.action == C.PA_NOOP:
            p_noop += 1
        else:
            p_skip += 1
            if pplan.reason == C.PR_ADMIN:
                p_admin += 1
        principal_rows.append(
            {
                "workspace_id": ws_id,
                "host": state.get("host"),
                "principal_type": pr.get("principal_type"),
                "principal_id": str(pr.get("principal_id")),
                "identifier": pr.get("identifier"),
                "display_name": pr.get("display_name"),
                "active": pr.get("active"),
                "is_admin": pr.get("is_admin"),
                "reachable_groups": as_list(pr.get("reachable_groups")),
                "entitlements_before": sorted(as_list(pr.get("direct_entitlements"))),
                "missing": pplan.missing,
                "action": pplan.action,
                "reason": pplan.reason,
                "direct_principals_mode": conf.direct_principals,
            }
        )

    verdict_rows.append(
        {
            "workspace_id": ws_id,
            # apply re-scopes with the same enforce_scope() call, and a name pattern needs the NAME.
            # Omitting it here is what made apply select zero workspaces (see entl_common.enforce_scope).
            "workspace_name": state.get("workspace_name") or inv_names.get(ws_id),
            "host": state.get("host"),
            "cloud": conf.cloud,
            "migration_state": state.get("state"),
            "migration_reason": state.get("reason"),
            "admin_ok": state.get("admin_ok"),
            "users_entitlements": sorted(users_ents),
            "users_extra_entitlements": sorted(users_ents - TARGETS),
            # which group the verdict was actually read from, and what it held. On a migrated workspace
            # under clone_fallback this is the clone, not `users` -- the report never hides that.
            "gate_source": gate.source,
            "gate_entitlements": gate.entitlements,
            "gate_extra_entitlements": sorted(set(gate.entitlements) - TARGETS),
            "clone_group_id": str(clone_gid) if clone_gid else None,
            "migrated_workspaces_mode": conf.migrated_workspaces,
            "verdict": verdict,
            "reason": reason,
            "groups_total": len(ws_groups),
            "groups_by_classification": by_class,
            "groups_to_grant": grant_count,
            "groups_already_correct": noop_count,
            "principals_total": len(ws_principals),
            "principals_access_only_via_users": sum(1 for p in ws_principals if p.get("access_only_via_users")),
            "principals_to_grant": p_grant,
            "principals_already_correct": p_noop,
            "principals_admin_excluded": p_admin,
            "principals_skipped": p_skip,
            "direct_principals_mode": conf.direct_principals,
            "aad_detection": conf.aad_detection,
        }
    )

# COMMAND ----------

writer.write("ws_verdict", verdict_rows)
writer.write("group_action", action_rows)
writer.write("principal_action", principal_rows)

proceed = [v for v in verdict_rows if v["verdict"] == C.V_PROCEED]
skipped = [v for v in verdict_rows if v["verdict"] == C.V_SKIP]
by_reason: dict[str, int] = {}
for v in skipped:
    by_reason[str(v["reason"])] = by_reason.get(str(v["reason"]), 0) + 1
grants = sum(v["groups_to_grant"] for v in verdict_rows)
noops = sum(v["groups_already_correct"] for v in verdict_rows)
standalone = sum(v["principals_access_only_via_users"] for v in verdict_rows)
p_grants = sum(v["principals_to_grant"] for v in verdict_rows)
p_noops = sum(v["principals_already_correct"] for v in verdict_rows)
p_admins = sum(v["principals_admin_excluded"] for v in verdict_rows)
p_by_reason: dict[str, int] = {}
for r in principal_rows:
    if r["action"] == "SKIP":
        p_by_reason[str(r["reason"])] = p_by_reason.get(str(r["reason"]), 0) + 1

print("-" * 78)
by_gate: dict[str, int] = {}
for v in proceed:
    by_gate[str(v["gate_source"])] = by_gate.get(str(v["gate_source"]), 0) + 1
print(f"PROCEED {len(proceed)} workspaces | SKIP {len(skipped)}")
if conf.migrated_workspaces == "clone_fallback":
    print(f"   gate source for the PROCEED set: {by_gate}   "
          f"(clone = already-migrated workspaces brought back in scope)")
for reason, count in sorted(by_reason.items(), key=lambda kv: -kv[1]):
    print(f"   {reason:28} {count}")
print(f"groups to grant: {grants} | already correct: {noops}")
print(f"principals whose access is ONLY via `users` (group grants cannot reach these): {standalone}")
print(f"direct_principals={conf.direct_principals} | principals to grant: {p_grants} | "
      f"already correct: {p_noops} | admins excluded (never touched): {p_admins}")
for reason, count in sorted(p_by_reason.items(), key=lambda kv: -kv[1]):
    print(f"   {reason:34} {count}")
if grants:
    est_serial = grants / 0.75
    print(f"estimated apply time: ~{est_serial / max(conf.workspaces_in_flight, 1) / 60:.0f} min "
          f"at ~0.75 writes/s per workspace, {conf.workspaces_in_flight} workspaces in flight")
print("\nreview ws_verdict + group_action + principal_action, then run task 3 with "
      "confirm_apply=GRANT-ENTITLEMENTS")
C.emit_summary({
    "task": "plan",
    "run_id": conf.run_id,
    "proceed": len(proceed),
    "skip": len(skipped),
    "skip_reasons": by_reason,
    "groups_to_grant": grants,
    "groups_already_correct": noops,
    "principals_access_only_via_users": standalone,
    "principals_to_grant": p_grants,
    "principals_already_correct": p_noops,
    "principals_admin_excluded": p_admins,
    "principal_skip_reasons": p_by_reason,
    "direct_principals": conf.direct_principals,
    "aad_detection": conf.aad_detection,
    "migrated_workspaces": conf.migrated_workspaces,
    "proceed_by_gate_source": by_gate,
})

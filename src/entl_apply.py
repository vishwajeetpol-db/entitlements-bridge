# Databricks notebook source
# MAGIC %md
# MAGIC # Task 3 of 3 — apply (GATED, mutates)
# MAGIC
# MAGIC Executes only the `GRANT` rows from the plan. Refuses to do anything unless
# MAGIC `confirm_apply=GRANT-ENTITLEMENTS`.
# MAGIC
# MAGIC Two target types, both gated by the same workspace verdict:
# MAGIC   * **groups** — AAD account groups, from `group_action`. Unchanged.
# MAGIC   * **principals** — from `principal_action`: non-admin users and service principals whose only
# MAGIC     group is `users`, so no group grant can reach them. Skipped entirely when
# MAGIC     `direct_principals=skip`. **Admins are never written to**, and that is re-checked live per
# MAGIC     principal, not merely trusted from the plan.
# MAGIC
# MAGIC Three safety properties, all of them load-bearing:
# MAGIC   1. **The gate is re-checked live.** A plan can be hours old. Before touching a workspace this task
# MAGIC      re-reads the migration state and the `users` entitlements, and abandons the workspace if the
# MAGIC      gate no longer holds.
# MAGIC   2. **Verify after write.** A no-op PATCH on a locked object returns success, so a 2xx proves
# MAGIC      nothing. Every group and principal is re-read and the result must contain `before ∪ targets`.
# MAGIC   3. **Circuit breaker.** If a pre-existing entitlement ever disappears, the whole run aborts. One
# MAGIC      workspace behaving differently must stop the fleet, not corrupt it quietly.
# MAGIC
# MAGIC Serial within a workspace, parallel across workspaces — the SCIM limiter is per workspace.

# COMMAND ----------

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)) if "__file__" in dir() else os.getcwd())

import entl_common as C  # noqa: E402

# COMMAND ----------

conf = C.load_conf()
C.banner(conf, "ENTITLEMENTS BRIDGE — 3/3 APPLY (mutates)")

REQUIRED_TOKEN = "GRANT-ENTITLEMENTS"
if conf.mode != "apply":
    raise SystemExit(f"this task requires mode=apply, got mode={conf.mode!r}")
if conf.confirm_apply != REQUIRED_TOKEN:
    raise SystemExit(
        f"refusing to mutate: set confirm_apply={REQUIRED_TOKEN} once the plan has been reviewed. "
        "Nothing has been changed."
    )

writer = C.Writer(conf)
client_id, client_secret = C.resolve_runner_credentials(conf)

actions = writer.read("group_action")
verdicts = writer.read("ws_verdict")
principal_actions = writer.read("principal_action")
if not actions:
    raise SystemExit("no group_action rows found — run task 2 (plan) first")

latest_ts = max(str(a.get("run_ts")) for a in actions)
actions = [a for a in actions if str(a.get("run_ts")) == latest_ts]
verdicts = [v for v in verdicts if str(v.get("run_ts")) == latest_ts]
# a plan written before the direct-principals path existed has no rows here at all, which is simply
# "no principal work", not an error. Same run_ts filter, so the two halves can never come from different runs.
principal_actions = [p for p in principal_actions if str(p.get("run_ts")) == latest_ts]
print(f"acting on plan generated at {latest_ts}")

allowed_ws = {str(v.get("workspace_id")) for v in verdicts if str(v.get("verdict")) == C.V_PROCEED}
grants = [a for a in actions
          if str(a.get("action")) == "GRANT" and str(a.get("workspace_id")) in allowed_ws]
pgrants = [p for p in principal_actions
           if str(p.get("action")) == C.PA_GRANT and str(p.get("workspace_id")) in allowed_ws]

groups_by_ws: dict[str, list[dict]] = {}
for a in grants:
    groups_by_ws.setdefault(str(a.get("workspace_id")), []).append(a)
principals_by_ws: dict[str, list[dict]] = {}
for pr in pgrants:
    principals_by_ws.setdefault(str(pr.get("workspace_id")), []).append(pr)
# union: a workspace can have principal work and no group work (every AAD group already correct)
all_ws = sorted(set(groups_by_ws) | set(principals_by_ws))

hosts = {str(v.get("workspace_id")): str(v.get("host")) for v in verdicts}
names = {str(v.get("workspace_id")): str(v.get("workspace_name") or "") for v in verdicts}
# enforce_scope must receive the workspace NAME, not just the id: with workspace_name_pattern set, rows
# without a name match nothing and the run granted ZERO groups while reporting SUCCESS. The guard now
# refuses such rows outright, so this is belt and braces -- but the name has to be supplied here.
scoped = C.enforce_scope(conf, [{"workspace_id": ws, "workspace_name": names.get(ws, "")}
                                for ws in all_ws])
work = [(str(r["workspace_id"]),
         groups_by_ws.get(str(r["workspace_id"]), []),
         principals_by_ws.get(str(r["workspace_id"]), []))
        for r in scoped]
print(f"apply scope: {len(work)} workspaces, {sum(len(g) for _, g, _ in work)} groups and "
      f"{sum(len(pr) for _, _, pr in work)} principals to grant "
      f"(direct_principals={conf.direct_principals})")

# COMMAND ----------

TARGETS = set(C.TARGET_ENTITLEMENTS)
abort = {"reason": None}


as_list = C.as_list  # one definition, shared with plan


def apply_workspace(item: tuple[str, list[dict], list[dict]]) -> list[dict]:
    ws_id, todo, ptodo = item
    host = hosts.get(ws_id) or str((todo or ptodo or [{}])[0].get("host") or "")
    rows: list[dict] = []
    if abort["reason"]:
        return rows
    session = C.WorkspaceSession(host, client_id, client_secret, ws_id)

    def outcome(group: dict, status: str, **extra) -> dict:
        return {
            "workspace_id": ws_id,
            "host": host,
            "target_type": "group",
            "group_id": str(group.get("group_id")),
            "display_name": group.get("display_name"),
            "classification": group.get("classification"),
            "status": status,
            **extra,
        }

    def p_outcome(pr: dict, status: str, **extra) -> dict:
        return {
            "workspace_id": ws_id,
            "host": host,
            "target_type": "principal",
            "principal_type": pr.get("principal_type"),
            "principal_id": str(pr.get("principal_id")),
            "identifier": pr.get("identifier"),
            "display_name": pr.get("display_name"),
            "is_admin": pr.get("is_admin"),
            "status": status,
            **extra,
        }

    def abandon(status: str, **extra) -> list[dict]:
        """A workspace-level abandonment applies to BOTH paths -- neither may proceed alone."""
        return ([outcome(g, status, **extra) for g in todo]
                + [p_outcome(pr, status, **extra) for pr in ptodo])

    # 1. re-check the gate live — the plan may be stale. Same question as the plan asked, by construction:
    #    both call C.gate_workspace, so the two can never drift apart.
    record, admin_ok, err = session.admin_probe()
    if not admin_ok:
        print(f"  {ws_id} ABANDONED: no longer workspace admin")
        return abandon("ABANDONED_NOT_ADMIN", http_error=err)
    state = str(record.get("state")) if record else None
    clone_gid = (record or {}).get("group_id")
    if state == "ENABLED" and conf.migrated_workspaces != "clone_fallback":
        print(f"  {ws_id} ABANDONED: workspace migrated since the plan was made")
        return abandon("ABANDONED_ALREADY_MIGRATED")

    live_groups, gerr = session.scim_pages(
        "Groups", C.GROUP_ATTRS_LIGHT
    )
    if gerr:
        print(f"  {ws_id} ABANDONED: group read failed")
        return abandon("ABANDONED_READ_FAILED", http_error=gerr)
    users_group = next((g for g in live_groups if str(g.get("displayName")) == "users"), None)
    clone_group = C.find_clone_group(live_groups, clone_gid) if state == "ENABLED" else None
    gate = C.gate_workspace(
        admin_ok=True,
        migration_state=state,
        users=C.group_ents_from_scim(users_group),
        clone=C.group_ents_from_scim(clone_group),
        clone_group_id=clone_gid,
        migrated_workspaces=conf.migrated_workspaces,
    )
    if gate.verdict != C.V_PROCEED:
        print(f"  {ws_id} ABANDONED: gate no longer holds — {gate.reason} "
              f"(read from `{gate.source}`: {gate.entitlements})")
        return abandon("ABANDONED_GATE_CHANGED", entitlements_before=gate.entitlements,
                       gate_reason=gate.reason, gate_source=gate.source)
    if gate.source == "clone":
        print(f"  {ws_id} proceeding on the migration clone group {clone_gid} ({gate.entitlements})")

    def grant_one(label, live, precheck_err, refetch, write, row_builder, trust=C.read_trustworthy) -> str:
        """Write-and-verify for ONE object, group or principal.

        Lives in one place on purpose: the circuit breaker is the property that stops a misbehaving
        workspace from quietly corrupting the fleet, and a second copy of it is a second chance to get it
        wrong. `live` is passed in rather than read here so the caller's pre-check read is not repeated --
        SCIM rate limiting is per workspace and this runs once per object.
        """
        # `trust` differs by target type: groups are disambiguated by `meta`, principals by `active`,
        # because SCIM never returns `meta` for a User or ServicePrincipal (measured -- see entl_common).
        if live is None or not trust(live):
            rows.append(row_builder("FAILED_PRECHECK",
                                    http_error=precheck_err or "entitlements attribute absent"))
            return "failed"
        before = set(C.entitlements_of(live))
        missing = sorted(TARGETS - before)
        if not missing:
            rows.append(row_builder("NOOP", entitlements_before=sorted(before),
                                    added=[], entitlements_after=sorted(before), verified=True))
            return "noop"

        perr = write(missing)
        after_obj, _aerr = refetch()
        after = set(C.entitlements_of(after_obj)) if after_obj is not None else set()

        # circuit breaker: nothing that existed before may vanish
        if after_obj is not None and C.has_entitlements_attr(after_obj) and not before <= after:
            lost = sorted(before - after)
            abort["reason"] = (
                f"workspace {ws_id} {label} lost entitlements {lost} after PATCH "
                f"— halting the entire run"
            )
            rows.append(row_builder("FAILED_ENTITLEMENT_LOSS", entitlements_before=sorted(before),
                                    added=missing, entitlements_after=sorted(after), verified=False,
                                    http_error=perr))
            print("  !! " + abort["reason"])
            return "lost"

        verified = TARGETS <= after
        if perr and not verified:
            rows.append(row_builder("FAILED", entitlements_before=sorted(before), added=[],
                                    entitlements_after=sorted(after), verified=False, http_error=perr))
            return "failed"
        rows.append(row_builder("GRANTED" if verified else "FAILED_UNVERIFIED",
                                entitlements_before=sorted(before), added=missing,
                                entitlements_after=sorted(after), verified=verified, http_error=perr))
        return "granted" if verified else "failed"

    # ---- path 1: AAD account groups (unchanged) --------------------------------------------------
    granted = noop = failed = 0
    for group in todo:
        if abort["reason"]:
            rows.append(outcome(group, "ABORTED_RUN_HALTED"))
            continue
        gid = str(group.get("group_id"))
        status = grant_one(
            f"group {gid} ({group.get('display_name')})",
            *session.get_group(gid, C.GROUP_ATTRS_LIGHT),
            lambda: session.get_group(gid, C.GROUP_ATTRS_LIGHT),
            lambda values: session.add_entitlements(gid, values),
            lambda st, **extra: outcome(group, st, **extra),
        )
        if status == "lost":
            break
        granted += status == "granted"
        noop += status == "noop"
        failed += status == "failed"

    # ---- path 2: principals no group grant can reach -------------------------------------------
    p_granted = p_noop = p_failed = p_abandoned = 0
    for pr in ptodo:
        if abort["reason"]:
            rows.append(p_outcome(pr, "ABORTED_RUN_HALTED"))
            continue
        ptype = str(pr.get("principal_type"))
        pid = str(pr.get("principal_id"))
        attrs = C.USER_ATTRS if ptype == "user" else C.SP_ATTRS
        live, rerr = session.get_principal(ptype, pid, attrs)

        # Re-ask the SCOPE question live, exactly as the workspace gate is re-asked above: an identity
        # can have been made an admin, added to a group, or deactivated since the plan was written, and
        # "we will not touch admins" has to hold at write time, not just at plan time.
        if live is not None:
            recheck = C.plan_principal(
                group_names=C.group_names_of(live),
                direct_entitlements=C.entitlements_of(live),
                entitlements_trustworthy=C.principal_read_trustworthy(live),
                active=live.get("active"),
                ws_verdict=C.V_PROCEED,   # just re-verified for this workspace, above
                direct_principals=conf.direct_principals,
            )
            if recheck.action == C.PA_SKIP:
                rows.append(p_outcome(pr, "ABANDONED_SCOPE_CHANGED", scope_reason=recheck.reason,
                                      entitlements_before=sorted(C.entitlements_of(live))))
                p_abandoned += 1
                continue

        status = grant_one(
            f"{ptype} {pid} ({pr.get('identifier')})",
            live,
            rerr,
            lambda: session.get_principal(ptype, pid, attrs),
            lambda values: session.add_principal_entitlements(ptype, pid, values),
            lambda st, **extra: p_outcome(pr, st, **extra),
            trust=C.principal_read_trustworthy,
        )
        if status == "lost":
            break
        p_granted += status == "granted"
        p_noop += status == "noop"
        p_failed += status == "failed"

    print(f"  {ws_id} groups: granted={granted} noop={noop} failed={failed} | "
          f"principals: granted={p_granted} noop={p_noop} failed={p_failed} "
          f"abandoned={p_abandoned} | throttles={session.throttle_events}")
    return rows


# COMMAND ----------

results = C.fan_out(work, apply_workspace, conf.workspaces_in_flight)
rows: list[dict] = []
for r in results:
    rows.extend(r)
writer.write("apply_outcome", rows)

tally: dict[str, int] = {}
by_type: dict[str, dict[str, int]] = {}
for r in rows:
    status = str(r.get("status"))
    ttype = str(r.get("target_type") or "group")
    tally[status] = tally.get(status, 0) + 1
    by_type.setdefault(ttype, {})[status] = by_type.setdefault(ttype, {}).get(status, 0) + 1
print("-" * 78)
for ttype in sorted(by_type):
    print(f"  {ttype}:")
    for status, count in sorted(by_type[ttype].items(), key=lambda kv: -kv[1]):
        print(f"    {status:28} {count}")

C.emit_summary({
    "task": "apply",
    "run_id": conf.run_id,
    "workspaces": len(work),
    "outcomes": tally,
    "outcomes_by_target_type": by_type,
    "direct_principals": conf.direct_principals,
    "halted": abort["reason"],
})
if abort["reason"]:
    raise C.EntitlementLossError(abort["reason"])
if tally.get("FAILED", 0) or tally.get("FAILED_UNVERIFIED", 0) or tally.get("FAILED_PRECHECK", 0):
    print("\nsome grants failed — re-running apply is safe and will retry only what is still missing")

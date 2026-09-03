"""Shared plumbing for the entitlements bridge (audit / plan / apply).

Design notes that are NOT arbitrary — each was forced by a measured behaviour, see README §7:
  * Every SCIM read asks for its fields EXPLICITLY. A reduced response looks identical to an empty one:
    a non-admin group read returns id+displayName with HTTP 200 and no error, and the account-level group
    list silently omits externalId. A missing field therefore means UNKNOWN, never EMPTY.
  * The admin gate is the migration endpoint: 403 => not admin, 200+{} => admin and still on legacy
    behaviour, 200+body => opted in or out. Nothing else is trusted until that call succeeds.
  * The SCIM rate limiter is per workspace. Work is parallel ACROSS workspaces and strictly SERIAL
    within one; bursting inside a single workspace collapses throughput instead of raising it.
  * Writes are verified by re-reading. A no-op PATCH on a locked system group returns success, so a
    2xx is not proof that anything was applied.
"""
from __future__ import annotations

import base64
import fnmatch
import json
import os
import random
import re
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable, NamedTuple

# ---------------------------------------------------------------- constants

TARGET_ENTITLEMENTS: tuple[str, ...] = ("workspace-access", "databricks-sql-access")
SYSTEM_GROUPS: tuple[str, ...] = ("users", "admins")
CLONE_NAME_PREFIX = "users-clone-"

GUID_RE = re.compile(r"^[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$")

GROUP_ATTRS = "id,displayName,externalId,meta,entitlements,members"
GROUP_ATTRS_LIGHT = "id,displayName,externalId,meta,entitlements"
# NOTE: `meta` is deliberately NOT requested here. Measured 2026-09-02 against live SCIM (list, single
# GET, and unprojected): Users and ServicePrincipals never carry `meta`, while Groups always do. Asking
# for it would imply the group trust test applies to principals -- see principal_read_trustworthy().
USER_ATTRS = "id,userName,displayName,active,entitlements,groups"
SP_ATTRS = "id,applicationId,displayName,active,entitlements,groups"
# principal_type (as written by the audit) -> SCIM collection. Users and ServicePrincipals take the
# same PATCH shape as Groups, so one code path serves both.
SCIM_RESOURCE = {"user": "Users", "service_principal": "ServicePrincipals"}

MIGRATION_PATH = "/api/2.0/preview/access-control/entitlements-migration"
ACCOUNT_HOSTS = {"aws": "accounts.cloud.databricks.com", "azure": "accounts.azuredatabricks.net"}
SCIM = "/api/2.0/preview/scim/v2"

# group classifications
CLS_AAD = "aad_account_group"
CLS_NATIVE = "native_account_group"
CLS_LOCAL = "workspace_local_group"
CLS_SYSTEM = "system_group"
CLS_CLONE = "migration_clone_group"

# workspace verdicts
V_PROCEED = "PROCEED"
V_SKIP = "SKIP"
R_MISSING_SQL = "USERS_MISSING_SQL"
R_MISSING_WS = "USERS_MISSING_WORKSPACE"
R_MISSING_BOTH = "USERS_MISSING_BOTH"
R_ALREADY = "ALREADY_MIGRATED"
R_NOT_ADMIN = "NOT_ADMIN"
R_NO_USERS_GROUP = "USERS_GROUP_NOT_FOUND"
R_READ_FAILED = "WORKSPACE_READ_FAILED"
# migrated workspaces, only reachable when migrated_workspaces=clone_fallback (README §3, CONTEXT §7)
R_NO_CLONE_GROUP = "NO_CLONE_GROUP"              # `users` held nothing at migration => no clone was created
R_CLONE_NOT_FOUND = "CLONE_GROUP_NOT_FOUND"      # the record names a clone we could not read: not the same thing
R_CLONE_MISSING_SQL = "CLONE_MISSING_SQL"
R_CLONE_MISSING_WS = "CLONE_MISSING_WORKSPACE"
R_CLONE_MISSING_BOTH = "CLONE_MISSING_BOTH"

# per-principal actions (direct_principals path). A principal is in scope only when no group grant
# can reach it: `users` is the sole group it holds. Admins are carved out explicitly rather than
# incidentally -- they inherit all FIVE workspace entitlement flags through `admins`, never modified.
PA_GRANT = "GRANT"
PA_NOOP = "NOOP"
PA_SKIP = "SKIP"
PR_ADMIN = "ADMIN_INHERITS_VIA_ADMINS_GROUP"
PR_GROUP_MEMBER = "COVERED_BY_GROUP_GRANT"
PR_INACTIVE = "PRINCIPAL_INACTIVE"
PR_DISABLED = "DIRECT_PRINCIPALS_DISABLED"
PR_HAS_BOTH = "ALREADY_HAS_BOTH"
# an audit table written before the direct-principals path existed has no trust column at all.
# That is UNKNOWN, not EMPTY, so it is skipped -- with a reason that names the actual fix (re-audit).
PR_STALE_AUDIT = "AUDIT_PREDATES_DIRECT_PRINCIPALS"


class EntitlementLossError(RuntimeError):
    """Raised when a verify-after-write shows a pre-existing entitlement disappeared.

    This aborts the entire run on purpose. One workspace behaving differently from the other 699 must
    stop the fleet, not quietly corrupt it.
    """


# ---------------------------------------------------------------- config

@dataclass
class Conf:
    mode: str = "audit"                    # audit | plan | apply
    cloud: str = "aws"                     # aws | azure (one account per run)
    catalog: str = ""
    schema: str = ""
    secret_scope: str = ""
    runner_client_id_key: str = "runner_client_id"
    runner_client_secret_key: str = "runner_client_secret"
    inventory_table: str = ""              # <catalog>.<schema>.ws_inventory when unset
    workspace_id_allowlist: set[str] = field(default_factory=set)
    workspace_name_pattern: str = ""       # glob on workspace_name, e.g. "prod-*"
    allow_all_workspaces: bool = False
    max_workspaces: int = 0                # hard ceiling; 0 = off. Exceeding it REFUSES, never truncates
    batch_size: int = 0                    # 0 = no batching
    batch_index: int = 0                   # 0-based, used with batch_size
    workspaces_in_flight: int = 8          # parallelism ACROSS workspaces
    aad_detection: str = "external_id"     # external_id | all_account_groups
    migrated_workspaces: str = "skip"      # skip | clone_fallback
    direct_principals: str = "grant"       # grant | skip -- principals no group grant can reach
    # ---- inventory (Phase 0) only: needs an ACCOUNT ADMIN, used once, then handed off ----
    account_id: str = ""
    account_host: str = ""                 # defaults from cloud
    account_client_id_key: str = "account_client_id"
    account_client_secret_key: str = "account_client_secret"
    grant_runner_workspace_admin: bool = False   # off by default: enumerate, do not change permissions
    runner_sp_principal_id: str = ""       # numeric account id of the runner SP, only used when granting
    account_client_id: str = ""            # local run: from ENTL_ACCOUNT_CLIENT_ID
    account_client_secret: str = ""        # local run: from ENTL_ACCOUNT_CLIENT_SECRET
    account_token: str = ""                # local run: a ready account-scoped bearer token
    capture_members: bool = True
    confirm_apply: str = ""                # must equal "GRANT-ENTITLEMENTS" for mode=apply
    output: str = "delta"                  # delta | json
    out_dir: str = "./out"
    run_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    run_ts: str = field(default_factory=lambda: time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
    # local run only: skip the secret scope and take the runner creds from the environment
    client_id: str = ""
    client_secret: str = ""

    @property
    def tables_prefix(self) -> str:
        return f"{self.catalog}.{self.schema}" if self.catalog and self.schema else ""

    def table(self, name: str) -> str:
        return f"{self.tables_prefix}.{name}" if self.tables_prefix else name


_SPEC: list[tuple[str, str, str]] = [
    # (name, default, help)
    ("mode", "audit", "audit | plan | apply"),
    ("cloud", "aws", "aws | azure"),
    ("catalog", "", "UC catalog (must already exist)"),
    ("schema", "", "UC schema (must already exist)"),
    ("secret_scope", "", "secret scope holding the runner OAuth credentials"),
    ("runner_client_id_key", "runner_client_id", "secret key for the runner client id"),
    ("runner_client_secret_key", "runner_client_secret", "secret key for the runner client secret"),
    ("inventory_table", "", "fully qualified inventory table (defaults to <catalog>.<schema>.ws_inventory)"),
    ("workspace_id_allowlist", "", "comma separated workspace ids; empty NEVER means all"),
    ("workspace_name_pattern", "", "glob on workspace_name, e.g. 'prod-*'; combines with the allowlist as AND"),
    ("allow_all_workspaces", "false", "true for a deliberate whole-account run"),
    ("max_workspaces", "0", "safety ceiling: refuse (never truncate) if the selection exceeds this. 0 = off"),
    ("batch_size", "0", "process the fleet in batches of this size; 0 = no batching"),
    ("batch_index", "0", "which batch to run, 0-based"),
    ("workspaces_in_flight", "8", "how many workspaces to process concurrently"),
    ("aad_detection", "external_id", "external_id | all_account_groups"),
    ("migrated_workspaces", "skip", "skip | clone_fallback (gate migrated workspaces on the clone group)"),
    ("direct_principals", "grant", "grant | skip: non-admin users/SPs whose only group is `users`"),
    ("account_id", "", "Databricks account id — inventory task only"),
    ("account_host", "", "account console host; defaults from cloud"),
    ("account_client_id_key", "account_client_id", "secret key for the ACCOUNT ADMIN client id"),
    ("account_client_secret_key", "account_client_secret", "secret key for the ACCOUNT ADMIN client secret"),
    ("grant_runner_workspace_admin", "false", "also grant the runner SP workspace ADMIN on each workspace"),
    ("runner_sp_principal_id", "", "numeric account id of the runner SP (only needed when granting)"),
    ("capture_members", "true", "capture group membership rows"),
    ("confirm_apply", "", "type GRANT-ENTITLEMENTS to allow mode=apply to mutate"),
    ("output", "delta", "delta | json"),
    ("out_dir", "./out", "output directory when output=json"),
]


def load_conf(argv: list[str] | None = None) -> Conf:
    """Read config from notebook widgets when running as a job, else from argv."""
    raw: dict[str, str] = {name: default for name, default, _ in _SPEC}
    dbu = _dbutils()
    if dbu is not None:
        for name, default, helptext in _SPEC:
            try:
                dbu.widgets.text(name, default, helptext)
            except Exception:
                pass
        for name, _, _ in _SPEC:
            try:
                raw[name] = (dbu.widgets.get(name) or "").strip()
            except Exception:
                pass
    else:
        import argparse

        p = argparse.ArgumentParser(description="entitlements bridge")
        for name, default, helptext in _SPEC:
            p.add_argument(f"--{name}", default=default, help=helptext)
        ns = p.parse_args(argv)
        raw = {name: str(getattr(ns, name)).strip() for name, _, _ in _SPEC}

    conf = Conf(
        mode=raw["mode"].lower(),
        cloud=raw["cloud"].lower(),
        catalog=raw["catalog"],
        schema=raw["schema"],
        secret_scope=raw["secret_scope"],
        runner_client_id_key=raw["runner_client_id_key"],
        runner_client_secret_key=raw["runner_client_secret_key"],
        inventory_table=raw["inventory_table"],
        workspace_id_allowlist={w.strip() for w in raw["workspace_id_allowlist"].split(",") if w.strip()},
        workspace_name_pattern=raw["workspace_name_pattern"].strip(),
        allow_all_workspaces=raw["allow_all_workspaces"].lower() == "true",
        max_workspaces=max(0, int(raw["max_workspaces"] or "0")),
        batch_size=max(0, int(raw["batch_size"] or "0")),
        batch_index=max(0, int(raw["batch_index"] or "0")),
        workspaces_in_flight=max(1, int(raw["workspaces_in_flight"] or "8")),
        aad_detection=raw["aad_detection"].lower(),
        migrated_workspaces=raw["migrated_workspaces"].lower(),
        direct_principals=raw["direct_principals"].lower(),
        account_id=raw["account_id"].strip(),
        account_host=raw["account_host"].strip(),
        account_client_id_key=raw["account_client_id_key"],
        account_client_secret_key=raw["account_client_secret_key"],
        grant_runner_workspace_admin=raw["grant_runner_workspace_admin"].lower() == "true",
        runner_sp_principal_id=raw["runner_sp_principal_id"].strip(),
        account_client_id=os.environ.get("ENTL_ACCOUNT_CLIENT_ID", ""),
        account_client_secret=os.environ.get("ENTL_ACCOUNT_CLIENT_SECRET", ""),
        account_token=os.environ.get("ENTL_ACCOUNT_TOKEN", ""),
        capture_members=raw["capture_members"].lower() == "true",
        confirm_apply=raw["confirm_apply"],
        output=raw["output"].lower(),
        out_dir=raw["out_dir"],
        client_id=os.environ.get("ENTL_CLIENT_ID", ""),
        client_secret=os.environ.get("ENTL_CLIENT_SECRET", ""),
    )
    if conf.mode not in ("audit", "plan", "apply", "inventory"):
        raise ValueError(f"mode must be audit|plan|apply|inventory, got {conf.mode!r}")
    if conf.cloud not in ("aws", "azure"):
        raise ValueError(f"cloud must be aws|azure, got {conf.cloud!r}")
    if conf.aad_detection not in ("external_id", "all_account_groups"):
        raise ValueError(f"aad_detection must be external_id|all_account_groups, got {conf.aad_detection!r}")
    if conf.migrated_workspaces not in ("skip", "clone_fallback"):
        raise ValueError(
            f"migrated_workspaces must be skip|clone_fallback, got {conf.migrated_workspaces!r}"
        )
    # Refuse rather than fall through: every value except "grant" disables the path, so a typo would
    # silently grant nothing to any principal and still report success.
    if conf.direct_principals not in ("grant", "skip"):
        raise ValueError(f"direct_principals must be grant|skip, got {conf.direct_principals!r}")
    # Placeholders shipped in databricks.yml must never reach a live call. Left unresolved, `catalog` and
    # `schema` build a table name like `<catalog>.<schema>.ws_inventory`, which fails deep inside Spark
    # with a parser error that names neither the variable nor databricks.yml.
    # `cloud` and `account_id` are in this list as of 2026-09-03: they are REQUIRED but had no placeholder
    # in the target block, so a customer following the guide reached job 0 and got
    # "inventory task needs account_id" -- or worse on Azure, where `cloud` defaulting to aws derives the
    # wrong account host and the platform answers with an opaque 400 naming nothing.
    unresolved = [f"{k}={v!r}" for k, v in (("catalog", conf.catalog), ("schema", conf.schema),
                                            ("secret_scope", conf.secret_scope),
                                            ("cloud", conf.cloud), ("account_id", conf.account_id))
                  if "<" in str(v) and ">" in str(v)]
    if unresolved:
        raise SystemExit(
            f"refusing to run: {', '.join(unresolved)} still holds the placeholder value shipped in "
            "databricks.yml. Replace it with your real catalog / schema / secret scope, cloud "
            "(aws|azure) and Databricks account id."
        )
    if not conf.account_host:
        conf.account_host = ACCOUNT_HOSTS.get(conf.cloud, "")
    if not conf.inventory_table and conf.tables_prefix:
        conf.inventory_table = conf.table("ws_inventory")
    return conf


def _dbutils():
    try:  # inside a Databricks notebook task
        return sys.modules["__main__"].dbutils  # type: ignore[attr-defined]
    except Exception:
        try:
            from pyspark.dbutils import DBUtils  # type: ignore

            from pyspark.sql import SparkSession

            return DBUtils(SparkSession.getActiveSession())
        except Exception:
            return None


def spark_or_none():
    try:
        from pyspark.sql import SparkSession

        return SparkSession.getActiveSession()
    except Exception:
        return None


def enforce_scope(conf: Conf, rows: list[dict]) -> list[dict]:
    """Fail-closed blast-radius guard. Four selectors: one, batch, pattern, all.

    An empty allowlist NEVER means 'all'; a run must name its scope one of three ways, and the fourth
    (`allow_all_workspaces`) has to be set deliberately. Selectors **intersect**: setting both an allowlist
    and a name pattern requires a row to satisfy both, because in a shared account the stricter reading is
    always the safe one.

    `max_workspaces` is a brake, not a filter — if the selection exceeds it the run **refuses** rather than
    silently processing a prefix, because a truncated run that looks successful is worse than no run.
    Deliberate partial coverage is what `batch_size`/`batch_index` are for, and those announce themselves.
    """
    if not (conf.allow_all_workspaces or conf.workspace_id_allowlist or conf.workspace_name_pattern):
        raise SystemExit(
            "refusing to run: name the scope with workspace_id_allowlist and/or workspace_name_pattern, "
            "or set allow_all_workspaces=true for a deliberate whole-account run. "
            "An empty allowlist never means 'all'."
        )
    # An UNRESOLVED PLACEHOLDER is not a scope. databricks.yml ships the `validate` target with
    # workspace_id_allowlist: "<ws-id-1>,<ws-id-2>,<ws-id-3>", and a target variable beats a variable
    # default -- so a customer who scopes by NAME PATTERN and leaves the allowlist alone gets the pattern
    # intersected with three ids that do not exist. Measured 2026-09-03: task 0 selected 0 of 1,447
    # workspaces and reported SUCCESS, and task 1 then failed on the empty ws_inventory. Refuse instead.
    placeholders = []
    for label, value in (("workspace_id_allowlist", ",".join(sorted(conf.workspace_id_allowlist))),
                         ("workspace_name_pattern", conf.workspace_name_pattern),
                         ("inventory_table", conf.inventory_table)):
        v = str(value or "")
        if "<" in v and ">" in v:
            placeholders.append(f"{label}={v!r}")
    if placeholders:
        raise SystemExit(
            "refusing to run: these scope settings still hold the placeholder values shipped in "
            f"databricks.yml -- {', '.join(placeholders)}. Replace them with real values, or set them to "
            "an empty string if you are scoping another way. A placeholder intersects to nothing and would "
            "produce a run that selects zero workspaces and reports success."
        )

    total = len(rows)
    keep = list(rows)
    applied: list[str] = []

    if conf.workspace_id_allowlist:
        keep = [r for r in keep if str(r.get("workspace_id")) in conf.workspace_id_allowlist]
        applied.append(f"allowlist({len(conf.workspace_id_allowlist)} ids)")
    if conf.workspace_name_pattern:
        pat = conf.workspace_name_pattern
        # A name pattern cannot be evaluated on a row that carries no name. Silently dropping such rows
        # made this guard fail-OPEN in the worst way: `entl_apply` passed rows holding only
        # `workspace_id`, every row failed the pattern, and the job granted NOTHING while reporting
        # SUCCESS. A guard that cannot evaluate its selector must REFUSE, not quietly select nothing.
        # Measured 2026-09-02 in the clean room; apply had never been run with a name pattern before.
        nameless = [r for r in keep if not str(r.get("workspace_name") or "")]
        if nameless:
            raise SystemExit(
                f"refusing to run: workspace_name_pattern={pat!r} is set, but {len(nameless)} of "
                f"{len(keep)} rows carry no workspace_name, so the pattern cannot be evaluated on them. "
                f"This would silently select nothing. Ensure the caller supplies workspace_name "
                f"(ws_inventory and ws_verdict both carry it)."
            )
        keep = [r for r in keep if fnmatch.fnmatch(str(r.get("workspace_name") or ""), pat)]
        applied.append(f"name_pattern({pat!r})")
    if not applied:
        applied.append("allow_all_workspaces=true")

    # A SCOPED run that matches nothing is a misconfiguration, not an empty estate. Same principle as
    # max_workspaces refusing rather than truncating: a run that reports success having touched nothing
    # hides the mistake. `total == 0` is different -- there was genuinely nothing to consider.
    if total > 0 and not keep and not conf.allow_all_workspaces:
        raise SystemExit(
            f"refusing to run: the scope selected 0 of {total} workspaces via {' AND '.join(applied)}. "
            "Selectors INTERSECT, so an allowlist plus a name pattern must both match the same workspace. "
            "Check the values, or use exactly one selector."
        )

    # deterministic order, so a given batch_index always means the same workspaces
    keep.sort(key=lambda r: str(r.get("workspace_id")))

    if conf.batch_size:
        batches = (len(keep) + conf.batch_size - 1) // conf.batch_size
        if conf.batch_index >= max(batches, 1):
            raise SystemExit(
                f"batch_index {conf.batch_index} is out of range: the selection of {len(keep)} workspaces "
                f"splits into {batches} batch(es) of {conf.batch_size} (valid indexes 0..{max(batches - 1, 0)})."
            )
        start = conf.batch_index * conf.batch_size
        keep = keep[start:start + conf.batch_size]
        applied.append(f"batch {conf.batch_index + 1} of {batches} (size {conf.batch_size})")

    if conf.max_workspaces and len(keep) > conf.max_workspaces:
        raise SystemExit(
            f"refusing to run: the scope selects {len(keep)} workspaces, above the max_workspaces ceiling "
            f"of {conf.max_workspaces}. Narrow the scope, use batch_size/batch_index, or raise the ceiling "
            "deliberately. The ceiling never truncates — a partial run that reports success is worse."
        )
    print(f"scope: {' + '.join(applied)} -> {len(keep)} of {total} workspaces")
    return keep


def resolve_runner_credentials(conf: Conf) -> tuple[str, str]:
    if conf.client_id and conf.client_secret:
        return conf.client_id, conf.client_secret
    dbu = _dbutils()
    if dbu is None or not conf.secret_scope:
        raise SystemExit(
            "no runner credentials: set ENTL_CLIENT_ID/ENTL_CLIENT_SECRET for a local run, or "
            "secret_scope plus the two key names for a job run."
        )
    return (
        dbu.secrets.get(conf.secret_scope, conf.runner_client_id_key),
        dbu.secrets.get(conf.secret_scope, conf.runner_client_secret_key),
    )


# ---------------------------------------------------------------- http

@dataclass
class ApiResult:
    body: Any | None
    status: int | None
    error: str | None

    @property
    def ok(self) -> bool:
        return self.error is None


class AccountSession:
    """The ACCOUNT console API, used by the inventory task only — and by nothing else, ever.

    Kept deliberately separate from `WorkspaceSession` because the auth is genuinely different, and getting
    it wrong is the classic failure here: a workspace token is minted at `{workspace_host}/oidc/v1/token`,
    while an account token comes from **`{account_host}/oidc/accounts/{account_id}/v1/token`**. The second
    form is mandatory for `/api/2.0/accounts/...` and no workspace credential substitutes for it.

    Two credential sources, so the same code serves both a job and a hands-on run:
      * `client_credentials` with an account-admin **service principal** — what a scheduled job uses.
      * a ready account-scoped **bearer token** (`ENTL_ACCOUNT_TOKEN`) — what an account admin running this
        interactively already has, e.g. from `databricks auth token -p <account-profile>`. `client_credentials`
        is an SP-only grant, so a human identity can only arrive this way.
    """

    MAX_ATTEMPTS = 5

    def __init__(self, conf: Conf):
        self.conf = conf
        self.host = "https://" + (conf.account_host or "").replace("https://", "").rstrip("/")
        self.account_id = conf.account_id
        self._static_token = conf.account_token or ""
        self._cid, self._csec = "", ""
        self._token: str | None = self._static_token or None
        self._token_exp = float("inf") if self._static_token else 0.0
        self._lock = threading.Lock()
        if not self._static_token:
            self._cid, self._csec = self._resolve_credentials()
        if not self.account_id:
            raise SystemExit("inventory task needs account_id — the Databricks account this run enumerates.")

    def _resolve_credentials(self) -> tuple[str, str]:
        if self.conf.account_client_id and self.conf.account_client_secret:
            return self.conf.account_client_id, self.conf.account_client_secret
        dbu = _dbutils()
        if dbu is not None and self.conf.secret_scope:
            return (dbu.secrets.get(self.conf.secret_scope, self.conf.account_client_id_key),
                    dbu.secrets.get(self.conf.secret_scope, self.conf.account_client_secret_key))
        raise SystemExit(
            "no account-admin credentials. Either set ENTL_ACCOUNT_CLIENT_ID/ENTL_ACCOUNT_CLIENT_SECRET "
            "(or ENTL_ACCOUNT_TOKEN for an interactive account-admin run), or put the account-admin SP "
            "credentials in the secret scope under account_client_id_key / account_client_secret_key."
        )

    def _fresh_token(self) -> str:
        data = urllib.parse.urlencode({"grant_type": "client_credentials", "scope": "all-apis"}).encode()
        # NOTE the path: /oidc/accounts/<account_id>/v1/token, not the workspace form /oidc/v1/token
        req = urllib.request.Request(
            f"{self.host}/oidc/accounts/{self.account_id}/v1/token", data=data, method="POST")
        basic = base64.b64encode(f"{self._cid}:{self._csec}".encode()).decode()
        req.add_header("Authorization", f"Basic {basic}")
        req.add_header("Content-Type", "application/x-www-form-urlencoded")
        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                payload = json.loads(resp.read())
        except urllib.error.HTTPError as e:
            # A bare "HTTP Error 400: Bad Request" here names nothing actionable, and every common cause is
            # a mismatch between three settings that must agree. Measured 2026-09-03: `cloud` was left at
            # its default `aws` on an AZURE run, so account_host resolved to the AWS console while
            # account_id and the SP credentials were Azure. The 400 said none of that.
            try:
                detail = e.read().decode()[:300]
            except Exception:                                          # noqa: BLE001
                detail = ""
            raise SystemExit(
                f"account token request failed: HTTP {e.code} {detail}\n"
                f"  endpoint    : {self.host}/oidc/accounts/{self.account_id}/v1/token\n"
                f"  account_host: {self.host}  (derived from `cloud` unless account_host is set explicitly)\n"
                f"  account_id  : {self.account_id}\n"
                "  account_host, account_id and the secret-scope credentials must all belong to the SAME\n"
                "  account. An azure account_id against the AWS account host returns exactly this 400."
            ) from None
        self._token_exp = time.time() + int(payload.get("expires_in", 3600)) - 120
        return payload["access_token"]

    def token(self) -> str:
        with self._lock:
            if self._token is None or time.time() >= self._token_exp:
                self._token = self._fresh_token()
            return self._token

    def api(self, verb: str, path: str, body: Any = None) -> ApiResult:
        """Account API call. Refreshes once on 401, retries on 429/5xx with backoff."""
        url = f"{self.host}/api/2.0/accounts/{self.account_id}{path}"
        for attempt in range(self.MAX_ATTEMPTS):
            data = json.dumps(body).encode() if body is not None else None
            req = urllib.request.Request(url, data=data, method=verb.upper())
            req.add_header("Authorization", "Bearer " + self.token())
            if data:
                req.add_header("Content-Type", "application/json")
            try:
                with urllib.request.urlopen(req, timeout=90) as resp:
                    raw = resp.read()
                    return ApiResult(json.loads(raw) if raw.strip() else {}, resp.status, None)
            except urllib.error.HTTPError as exc:
                detail = exc.read().decode("utf-8", "replace")[:400]
                if exc.code == 401 and attempt == 0 and not self._static_token:
                    with self._lock:          # a long run can outlive the token; re-mint once
                        self._token = None
                    continue
                if exc.code in (429, 500, 502, 503, 504) and attempt < self.MAX_ATTEMPTS - 1:
                    time.sleep(min(2 ** attempt + random.random(), 20))
                    continue
                return ApiResult(None, exc.code, f"HTTP {exc.code}: {detail}")
            except Exception as exc:  # noqa: BLE001
                if attempt < self.MAX_ATTEMPTS - 1:
                    time.sleep(min(2 ** attempt + random.random(), 20))
                    continue
                return ApiResult(None, None, f"{type(exc).__name__}: {exc}")
        return ApiResult(None, None, "retries exhausted")

    # -- the three things the inventory task needs ---------------------
    def list_workspaces(self) -> tuple[list[dict], str | None]:
        """Every workspace in the account. The response shape is not stable across accounts."""
        res = self.api("GET", "/workspaces")
        if res.error:
            return [], res.error
        body = res.body
        rows = body if isinstance(body, list) else (body.get("workspaces") or body.get("data") or [])
        return list(rows), None

    def permission_assignments(self, workspace_id: str) -> tuple[list[dict], str | None]:
        """Read-only: who is assigned to this workspace, and with what. Never modifies anything."""
        res = self.api("GET", f"/workspaces/{workspace_id}/permissionassignments")
        if res.error:
            return [], res.error
        return list((res.body or {}).get("permission_assignments") or []), None

    def grant_workspace_admin(self, workspace_id: str, principal_id: str) -> str | None:
        """Idempotent: re-granting an existing assignment returns success."""
        res = self.api("PUT", f"/workspaces/{workspace_id}/permissionassignments/principals/{principal_id}",
                       {"permissions": ["ADMIN"]})
        return res.error


def workspace_host_of(row: dict) -> str:
    """Derive the workspace URL from an account-API row.

    `workspace_fqdn` is present on **both** clouds now and is authoritative, so the override map the older
    tooling needed for Azure is obsolete (verified 2026-09-01 against both accounts). `deployment_name` is
    the fallback: on AWS it is a bare name needing the cloud suffix, on Azure it already carries the shard.
    """
    fqdn = str(row.get("workspace_fqdn") or "").strip()
    if fqdn:
        return "https://" + fqdn.replace("https://", "").rstrip("/")
    dep = str(row.get("deployment_name") or "").strip()
    if not dep:
        return ""
    if dep.startswith("adb-") or "azuredatabricks" in dep:
        return "https://" + (dep if dep.endswith(".azuredatabricks.net") else dep + ".azuredatabricks.net")
    return f"https://{dep}.cloud.databricks.com"


class WorkspaceSession:
    """One workspace, one session, one request at a time.

    The lock is the point: the SCIM limiter is per workspace, so concurrency here would only produce
    429 storms. Parallelism belongs at the workspace level, above this class.
    """

    MAX_ATTEMPTS = 6

    def __init__(self, host: str, client_id: str, client_secret: str, workspace_id: str | None = None):
        self.host = host.rstrip("/")
        self.workspace_id = str(workspace_id) if workspace_id is not None else ""
        self._cid = client_id
        self._csec = client_secret
        self._token: str | None = None
        self._token_exp = 0.0
        self._lock = threading.Lock()
        self.throttle_events = 0

    # -- auth ---------------------------------------------------------
    def _fresh_token(self) -> str:
        data = urllib.parse.urlencode({"grant_type": "client_credentials", "scope": "all-apis"}).encode()
        req = urllib.request.Request(f"{self.host}/oidc/v1/token", data=data, method="POST")
        basic = base64.b64encode(f"{self._cid}:{self._csec}".encode()).decode()
        req.add_header("Authorization", f"Basic {basic}")
        req.add_header("Content-Type", "application/x-www-form-urlencoded")
        with urllib.request.urlopen(req, timeout=60) as resp:
            payload = json.loads(resp.read())
        self._token_exp = time.time() + int(payload.get("expires_in", 3600)) - 120
        return payload["access_token"]

    def _bearer(self) -> str:
        if self._token is None or time.time() >= self._token_exp:
            self._token = self._fresh_token()
        return self._token

    # -- request ------------------------------------------------------
    def api(self, verb: str, path: str, body: dict | None = None) -> ApiResult:
        with self._lock:
            return self._api_locked(verb, path, body)

    def _api_locked(self, verb: str, path: str, body: dict | None) -> ApiResult:
        payload = json.dumps(body).encode() if body is not None else None
        last: ApiResult | None = None
        for attempt in range(self.MAX_ATTEMPTS):
            req = urllib.request.Request(self.host + path, data=payload, method=verb)
            req.add_header("Authorization", f"Bearer {self._bearer()}")
            if payload is not None:
                req.add_header("Content-Type", "application/json")
            try:
                with urllib.request.urlopen(req, timeout=120) as resp:
                    raw = resp.read()
                    parsed = json.loads(raw) if raw.strip() else {}
                    return ApiResult(parsed, resp.status, None)
            except urllib.error.HTTPError as exc:
                detail = exc.read().decode(errors="replace")[:500]
                last = ApiResult(None, exc.code, f"HTTP {exc.code}: {detail}")
                if exc.code == 429 or 500 <= exc.code < 600:
                    self.throttle_events += 1 if exc.code == 429 else 0
                    time.sleep(self._backoff(exc, attempt))
                    continue
                if exc.code == 401:  # token rejected: mint a new one once and retry
                    self._token = None
                    if attempt == 0:
                        continue
                return last
            except Exception as exc:  # network/DNS/timeout
                last = ApiResult(None, None, f"{type(exc).__name__}: {exc}")
                time.sleep(self._backoff(None, attempt))
        return last or ApiResult(None, None, "exhausted retries")

    @staticmethod
    def _backoff(exc: Any, attempt: int) -> float:
        retry_after = None
        try:
            retry_after = float(exc.headers.get("Retry-After")) if exc is not None else None
        except Exception:
            retry_after = None
        if retry_after:
            return min(retry_after, 30.0)
        return min(0.5 * (2 ** attempt), 16.0) + random.uniform(0, 0.4)

    # -- typed helpers ------------------------------------------------
    def admin_probe(self) -> tuple[dict | None, bool, str | None]:
        """Returns (migration_record_or_None, admin_ok, error).

        200 + {}   -> admin, workspace still on legacy behaviour (no migration record)
        200 + body -> admin, workspace has opted in or out
        403        -> NOT a workspace admin: nothing this workspace reports can be trusted
        """
        res = self.api("GET", MIGRATION_PATH)
        if res.ok:
            return (res.body or None), True, None
        if res.status == 403:
            return None, False, res.error
        return None, False, res.error

    def scim_pages(self, resource: str, attrs: str, page_size: int = 100) -> tuple[list[dict], str | None]:
        """Walk a SCIM collection. startIndex is 1-based and advances by the returned count."""
        out: list[dict] = []
        index = 1
        while True:
            q = urllib.parse.urlencode({"count": page_size, "startIndex": index, "attributes": attrs})
            res = self.api("GET", f"{SCIM}/{resource}?{q}")
            if not res.ok:
                return out, res.error
            body = res.body or {}
            page = body.get("Resources") or []
            out.extend(page)
            total = int(body.get("totalResults") or 0)
            if not page or len(out) >= total:
                return out, None
            index += len(page)

    def get_group(self, group_id: str, attrs: str = GROUP_ATTRS) -> tuple[dict | None, str | None]:
        res = self.api("GET", f"{SCIM}/Groups/{group_id}?{urllib.parse.urlencode({'attributes': attrs})}")
        return (res.body if res.ok else None), res.error

    def add_entitlements(self, group_id: str, values: Iterable[str]) -> str | None:
        return self._add_entitlements("Groups", group_id, values)

    def get_principal(self, principal_type: str, principal_id: str, attrs: str) -> tuple[dict | None, str | None]:
        """Re-read one User/ServicePrincipal, for the verify-after-write step."""
        resource = SCIM_RESOURCE.get(principal_type)
        if resource is None:
            return None, f"unknown principal_type {principal_type!r}"
        res = self.api("GET", f"{SCIM}/{resource}/{principal_id}?{urllib.parse.urlencode({'attributes': attrs})}")
        return (res.body if res.ok else None), res.error

    def add_principal_entitlements(
        self, principal_type: str, principal_id: str, values: Iterable[str]
    ) -> str | None:
        resource = SCIM_RESOURCE.get(principal_type)
        if resource is None:
            return f"unknown principal_type {principal_type!r}"
        return self._add_entitlements(resource, principal_id, values)

    def _add_entitlements(self, resource: str, object_id: str, values: Iterable[str]) -> str | None:
        """`op:add` APPENDS -- it never replaces the list, so nothing pre-existing is removed. The caller
        still verifies by re-read, because a no-op PATCH on a locked object also returns 2xx."""
        res = self.api(
            "PATCH",
            f"{SCIM}/{resource}/{object_id}",
            {
                "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
                "Operations": [
                    {"op": "add", "path": "entitlements", "value": [{"value": v} for v in values]}
                ],
            },
        )
        return res.error


# ---------------------------------------------------------------- SCIM shapes

def entitlements_of(obj: dict | None) -> list[str]:
    """Explicit-attribute discipline: absent field means UNKNOWN, so callers must check presence first."""
    return sorted({e.get("value") for e in (obj or {}).get("entitlements") or [] if e.get("value")})


def has_entitlements_attr(obj: dict | None) -> bool:
    return isinstance(obj, dict) and "entitlements" in obj


def principal_read_trustworthy(obj: dict | None) -> bool:
    """Was the projection honoured, for a User or ServicePrincipal? NOT the same test as read_trustworthy.

    Groups are disambiguated by `meta`. Principals cannot be: measured 2026-09-02 against live SCIM on a
    list, a single GET, and an unprojected read, no User or ServicePrincipal ever carries `meta`. Reusing
    the group test here marked all 20 clean-room principals UNKNOWN and would have skipped every one of
    them while reporting success -- the precise failure mode the explicit-attribute rule exists to stop.

    `active` is the discriminator instead: it comes back on every honoured principal read (measured on both
    collections), and the reduced projection that creates the ambiguity in the first place -- the non-admin
    read that returns HTTP 200 carrying only id + displayName -- does not include it. The workspace admin
    gate remains the primary defence; this is the same belt-and-braces `meta` gives the group path.
    """
    return isinstance(obj, dict) and "active" in obj


def read_trustworthy(obj: dict | None) -> bool:
    """Was the projection we asked for actually honoured?

    Subtle and worth stating, because getting it wrong breaks the fleet either way. SCIM omits
    `entitlements` entirely when a group has none, so "attribute absent" is ambiguous:
      * absent because the group genuinely holds nothing  -> EMPTY, act on it
      * absent because the response was reduced (non-admin read, or a list endpoint that silently drops
        fields) -> UNKNOWN, never act on it

    `meta` disambiguates: an admin read that asked for `meta` always gets it, while the reduced projection
    returns only id + displayName. So `meta` present => the projection was honoured => absent
    `entitlements` really does mean empty.
    """
    return isinstance(obj, dict) and bool(obj.get("meta"))


def resource_type(group: dict) -> str:
    return ((group.get("meta") or {}).get("resourceType")) or ""


def is_clone_group(group: dict) -> bool:
    return str(group.get("displayName") or "").startswith(CLONE_NAME_PREFIX)


def classify_group(group: dict, aad_detection: str, clone_group_id: Any = None) -> str:
    """Classification is by resourceType + externalId, never by name alone.

    The clone group is identified by the id the migration record reports, not only by its default
    `users-clone-*` name: a customer opting in deliberately can rename it, and then a name check misses it.
    """
    name = str(group.get("displayName") or "")
    rtype = resource_type(group)
    if name in SYSTEM_GROUPS and rtype == "WorkspaceGroup":
        return CLS_SYSTEM
    if clone_group_id is not None and str(group.get("id")) == str(clone_group_id):
        return CLS_CLONE
    if is_clone_group(group):
        return CLS_CLONE
    if rtype == "Group":
        ext = str(group.get("externalId") or "")
        if aad_detection == "all_account_groups":
            return CLS_AAD
        return CLS_AAD if ext else CLS_NATIVE
    return CLS_LOCAL


def looks_like_entra_object_id(value: str | None) -> bool:
    return bool(value) and bool(GUID_RE.match(value or ""))


def find_clone_group(groups: Iterable[dict], clone_group_id: Any = None) -> dict | None:
    """Locate the migration clone group, with the same precedence `classify_group` uses.

    The id from the migration record wins; the default `users-clone-*` name is only a fallback, because a
    clone can be renamed. Never the other way round -- V23 met a customer group *named* like an Entra group
    that was nothing of the kind, and the same trap applies here.
    """
    groups = list(groups)
    if clone_group_id:
        for g in groups:
            if str(g.get("id")) == str(clone_group_id):
                return g
    for g in groups:
        if is_clone_group(g):
            return g
    return None


# ------------------------------------------------- the workspace gate (ONE definition)

def as_list(value: Any) -> list[str]:
    """Entitlement lists survive a Delta round-trip as either a real list or its JSON string."""
    if value is None:
        return []
    if isinstance(value, list):
        return [str(v) for v in value]
    if isinstance(value, str):
        stripped = value.strip()
        if stripped.startswith("["):
            try:
                return [str(v) for v in json.loads(stripped)]
            except Exception:
                return []
        return [stripped] if stripped else []
    return []


class GroupEnts(NamedTuple):
    """One group's entitlements, normalised so the gate never needs to know where the row came from.

    `present` and `trustworthy` are separate on purpose: a group we did not read is not the same thing as a
    group that holds nothing, and neither is the same as a read whose projection was silently reduced.
    """

    present: bool
    trustworthy: bool
    entitlements: frozenset[str]


GROUP_ENTS_ABSENT = GroupEnts(False, False, frozenset())


def group_ents_from_scim(group: dict | None) -> GroupEnts:
    """From a live SCIM read (apply path)."""
    if group is None:
        return GROUP_ENTS_ABSENT
    return GroupEnts(True, read_trustworthy(group), frozenset(entitlements_of(group)))


def group_ents_from_row(row: dict | None) -> GroupEnts:
    """From an audit table row (plan path)."""
    if row is None:
        return GROUP_ENTS_ABSENT
    trustworthy = bool(row.get("read_trustworthy", row.get("entitlements_attr_present", True)))
    return GroupEnts(True, trustworthy, frozenset(as_list(row.get("entitlements"))))


@dataclass
class Gate:
    verdict: str
    reason: str | None
    source: str                 # "users" | "clone" | "none" -- which group the decision was read from
    entitlements: list[str]     # what that group held, for the report


def _subset_gate(g: GroupEnts, source: str, missing_sql: str, missing_ws: str, missing_both: str) -> Gate:
    """The subset rule itself: proceed only when the gate group holds BOTH targets. Extras never block."""
    ents = sorted(g.entitlements)
    if not g.trustworthy:
        # the projection was reduced, so this set is unknown rather than empty
        return Gate(V_SKIP, R_READ_FAILED, source, ents)
    if set(TARGET_ENTITLEMENTS) <= g.entitlements:
        return Gate(V_PROCEED, None, source, ents)
    if "workspace-access" in g.entitlements:
        return Gate(V_SKIP, missing_sql, source, ents)
    if "databricks-sql-access" in g.entitlements:
        return Gate(V_SKIP, missing_ws, source, ents)
    return Gate(V_SKIP, missing_both, source, ents)


def gate_workspace(
    *,
    admin_ok: bool,
    migration_state: Any,
    users: GroupEnts,
    clone: GroupEnts = GROUP_ENTS_ABSENT,
    clone_group_id: Any = None,
    migrated_workspaces: str = "skip",
) -> Gate:
    """May this workspace be changed at all? The ONLY definition -- plan and apply both call this.

    They must not re-implement it. The apply-time re-check exists precisely to catch a plan that has gone
    stale, and it can only do that if it asks a byte-identical question.

    On a legacy workspace the gate reads `users`, which still carries the entitlements every principal
    inherits. On a MIGRATED workspace `users` is empty by definition, so the gate can only read the
    migration clone group -- and only when `migrated_workspaces=clone_fallback` is set deliberately.

    That substitution is sound rather than convenient: the clone holds *exactly* what `users` held at the
    moment of migration (a faithful copy -- and no clone is created at all when there was nothing to copy),
    so the subset rule keeps its original meaning. It is not being relaxed, it is being asked of the group
    that now carries the answer. See CONTEXT.md §7.
    """
    if not admin_ok:
        return Gate(V_SKIP, R_NOT_ADMIN, "none", [])

    if str(migration_state) == "ENABLED":
        if migrated_workspaces != "clone_fallback":
            return Gate(V_SKIP, R_ALREADY, "none", [])
        if not clone.present:
            # "no clone" and "a clone we failed to read" are different problems with different fixes:
            # the first means `users` was already empty at migration and there is nothing to bridge,
            # the second means the record names a group our read did not return.
            return Gate(V_SKIP, R_CLONE_NOT_FOUND if clone_group_id else R_NO_CLONE_GROUP, "clone", [])
        return _subset_gate(clone, "clone", R_CLONE_MISSING_SQL, R_CLONE_MISSING_WS, R_CLONE_MISSING_BOTH)

    if not users.present:
        return Gate(V_SKIP, R_NO_USERS_GROUP, "users", [])
    return _subset_gate(users, "users", R_MISSING_SQL, R_MISSING_WS, R_MISSING_BOTH)


def group_names_of(principal: dict) -> list[str]:
    """The SCIM `groups` attribute is already flattened across nested groups."""
    return [str(g.get("display")) for g in (principal.get("groups") or []) if g.get("display")]


def is_admin_principal(group_names: Iterable[str]) -> bool:
    """Workspace admin == member of `admins`. Explicit, because the previous test was incidental: a
    principal in `admins` merely failed `access_only_via_users` for holding *some* group, which would stop
    being true the moment that predicate is loosened."""
    return "admins" in set(group_names)


def reachable_group_names(group_names: Iterable[str]) -> list[str]:
    """Groups a group grant could flow through. `users` is excluded because every principal is in it and it
    is never modified; `admins` is excluded because it is a system group handled by the admin carve-out."""
    return sorted({str(g) for g in group_names} - set(SYSTEM_GROUPS))


@dataclass
class PrincipalPlan:
    action: str                 # PA_GRANT | PA_NOOP | PA_SKIP
    reason: str | None
    missing: list[str]          # what a GRANT would add


def plan_principal(
    *,
    group_names: Iterable[str],
    direct_entitlements: Iterable[str],
    entitlements_trustworthy: bool,
    active: Any,
    ws_verdict: str,
    ws_reason: Any = None,
    direct_principals: str = "grant",
) -> PrincipalPlan:
    """May this ONE principal be granted, and what is missing? The only definition -- plan and apply both
    call it, for the same reason `gate_workspace` exists: the apply-time re-check can only catch a stale
    plan if it asks a byte-identical question.

    Scope, in order, most durable truth first:
      * admin            -> never touched. It inherits all five workspace entitlements via `admins`.
      * any real group    -> out of scope; the AAD account-group path already reaches it (path 1, unchanged).
      * inactive          -> skipped. Entitling a deactivated identity is noise, not access.
      * untrustworthy read-> skipped. Absent `entitlements` is UNKNOWN unless `meta` proves the projection
                             was honoured, and acting on UNKNOWN is how you grant to the wrong population.
      * workspace skipped -> the subset rule governs principals exactly as it governs groups.
    """
    names = list(group_names)
    if direct_principals != "grant":
        return PrincipalPlan(PA_SKIP, PR_DISABLED, [])
    if is_admin_principal(names):
        return PrincipalPlan(PA_SKIP, PR_ADMIN, [])
    reachable = reachable_group_names(names)
    if reachable:
        return PrincipalPlan(PA_SKIP, PR_GROUP_MEMBER, [])
    if active is False:
        return PrincipalPlan(PA_SKIP, PR_INACTIVE, [])
    if not entitlements_trustworthy:
        return PrincipalPlan(PA_SKIP, R_READ_FAILED, [])
    if ws_verdict != V_PROCEED:
        return PrincipalPlan(PA_SKIP, f"WORKSPACE_SKIPPED:{ws_reason}", [])
    missing = sorted(set(TARGET_ENTITLEMENTS) - {str(e) for e in direct_entitlements})
    if not missing:
        return PrincipalPlan(PA_NOOP, PR_HAS_BOTH, [])
    return PrincipalPlan(PA_GRANT, None, missing)


def effective_entitlements(principal: dict, group_entitlements: dict[str, list[str]]) -> list[str]:
    """What this principal can actually do today, direct + inherited.

    `users` is unioned UNCONDITIONALLY, and that is not a shortcut. SCIM does not report `users` in a
    principal's own `groups` attribute -- verified against a live workspace, where every principal appeared
    in `users`.members while its own `groups` listed only `admins`, or nothing at all. Trusting `groups`
    alone therefore under-reports every non-admin identity: a service principal that plainly held
    workspace-access through `users` was recorded has_effective_workspace_access=False, and the
    standalone-principals report would have told you it lacked access it had.

    Every workspace principal is a member of `users`, so crediting it is correct pre-migration; after
    migration `users` is empty and the union adds nothing.
    """
    eff = set(entitlements_of(principal))
    for name in group_names_of(principal):
        eff.update(group_entitlements.get(name, []))
    eff.update(group_entitlements.get("users", []))
    return sorted(eff)


# ---------------------------------------------------------------- output

class Writer:
    """Delta when a Spark session exists and output=delta, newline-delimited JSON otherwise."""

    def __init__(self, conf: Conf):
        self.conf = conf
        self.spark = spark_or_none() if conf.output == "delta" else None
        if conf.output == "delta" and self.spark is None:
            raise SystemExit("output=delta needs a Spark session; use --output json for a local run")
        if self.spark is None:
            os.makedirs(conf.out_dir, exist_ok=True)
        else:
            self._preflight_schema()
        self.counts: dict[str, int] = {}

    def _preflight_schema(self) -> None:
        """Fail in seconds if the destination is not usable, instead of after sweeping every workspace.

        The catalog and schema are INPUTS — you create them and grant the runner on them. This tool never
        issues CREATE CATALOG or CREATE SCHEMA; it only creates its own tables inside the schema you name.
        Checked up front because the alternative is a run that reads 700 workspaces and then dies on the
        write with a bare permission error.
        """
        conf = self.conf
        if not conf.catalog or not conf.schema:
            raise SystemExit(
                "output=delta needs both 'catalog' and 'schema'. They must already exist — this tool does "
                "not create them. See README §6."
            )
        target = f"{conf.catalog}.{conf.schema}"
        try:
            self.spark.sql(f"DESCRIBE SCHEMA {target}").collect()
        except Exception as exc:
            raise SystemExit(
                f"cannot use schema {target}: {exc}\n"
                "This tool never creates the catalog or the schema. Have an admin create them and grant the "
                "runner service principal:\n"
                f"  GRANT USE CATALOG ON CATALOG {conf.catalog} TO `<runner-sp-application-id>`;\n"
                f"  GRANT USE SCHEMA, CREATE TABLE, MODIFY, SELECT ON SCHEMA {target} "
                "TO `<runner-sp-application-id>`;\n"
                "See README §6 and prerequisites.sql."
            ) from exc
        print(f"preflight: schema {target} reachable (tables will be created inside it)")

    def write(self, table: str, rows: list[dict]) -> None:
        self.counts[table] = self.counts.get(table, 0) + len(rows)
        if not rows:
            print(f"  {table}: 0 rows")
            return
        stamped = [{"run_id": self.conf.run_id, "run_ts": self.conf.run_ts, **r} for r in rows]
        if self.spark is not None:
            fq = self.conf.table(table)
            safe = [_json_safe(r) for r in stamped]
            schema = _spark_schema(safe)
            df = self.spark.createDataFrame([_coerce(r, schema) for r in safe], schema=schema)
            df.write.mode("append").option("mergeSchema", "true").saveAsTable(fq)
            print(f"  {fq}: +{len(rows)} rows")
        else:
            path = os.path.join(self.conf.out_dir, f"{table}.jsonl")
            with open(path, "a", encoding="utf-8") as fh:
                for row in stamped:
                    fh.write(json.dumps(_json_safe(row), default=str) + "\n")
            print(f"  {path}: +{len(rows)} rows")

    def read(self, table: str) -> list[dict]:
        if self.spark is not None:
            return [r.asDict(recursive=True) for r in self.spark.table(self.conf.table(table)).collect()]
        path = os.path.join(self.conf.out_dir, f"{table}.jsonl")
        if not os.path.exists(path):
            return []
        with open(path, encoding="utf-8") as fh:
            return [json.loads(line) for line in fh if line.strip()]


def _spark_schema(rows: list[dict]):
    """Explicit schema, because inference cannot type a column that is null in every row.

    On a healthy fleet whole columns are legitimately all-null — `reason` when nothing was skipped,
    `probe_error` when every probe succeeded, `clone_group_id` before any workspace has migrated. Spark then
    raises CANNOT_DETERMINE_TYPE and the whole write fails. So: take the type from the first non-null value
    seen for each key and fall back to string.
    """
    from pyspark.sql.types import (ArrayType, BooleanType, LongType, StringType, StructField, StructType)

    keys: list[str] = []
    for row in rows:
        for key in row:
            if key not in keys:
                keys.append(key)
    fields = []
    for key in keys:
        spark_type = StringType()
        for row in rows:
            value = row.get(key)
            if value is None:
                continue
            if isinstance(value, bool):
                spark_type = BooleanType()
            elif isinstance(value, int):
                spark_type = LongType()
            elif isinstance(value, list):
                spark_type = ArrayType(StringType())
            else:
                spark_type = StringType()
            break
        fields.append(StructField(key, spark_type, True))
    return StructType(fields)


def _coerce(row: dict, schema) -> tuple:
    """Line the row up with the schema, in field order, converting values to match."""
    from pyspark.sql.types import ArrayType, BooleanType, LongType

    out = []
    for field in schema.fields:
        value = row.get(field.name)
        if value is None:
            out.append(None)
        elif isinstance(field.dataType, ArrayType):
            out.append([str(v) for v in (value if isinstance(value, list) else [value])])
        elif isinstance(field.dataType, BooleanType):
            out.append(bool(value))
        elif isinstance(field.dataType, LongType):
            try:
                out.append(int(value))
            except (TypeError, ValueError):
                out.append(None)
        else:
            out.append(value if isinstance(value, str) else str(value))
    return tuple(out)


def _json_safe(row: dict) -> dict:
    out = {}
    for key, value in row.items():
        if isinstance(value, (set, tuple)):
            out[key] = list(value)
        elif isinstance(value, dict):
            out[key] = json.dumps(value, default=str)
        else:
            out[key] = value
    return out


def read_inventory(conf: Conf, writer: Writer) -> list[dict]:
    """Inventory is produced once by an account admin; the runner needs no account access.

    The table is an INPUT, like the catalog and schema. It is not created here.
    """
    if writer.spark is not None and conf.inventory_table:
        try:
            rows = [r.asDict(recursive=True) for r in writer.spark.table(conf.inventory_table).collect()]
        except Exception as exc:
            raise SystemExit(
                f"cannot read the inventory table {conf.inventory_table}: {exc}\n"
                "This is an input you supply: one row per target workspace with at least "
                "cloud / workspace_id / host, loaded by an account admin. See README §6 and "
                "prerequisites.sql. Point 'inventory_table' at it if it is not "
                f"{conf.table('ws_inventory')}."
            ) from exc
    else:
        rows = writer.read("ws_inventory")
    # The inventory is append-only like every other table, so a re-run of the inventory task adds a new
    # generation rather than replacing the old one. Take the newest generation only — otherwise every
    # workspace would be processed once per historical run.
    stamps = {str(r.get("run_ts")) for r in rows if r.get("run_ts")}
    if len(stamps) > 1:
        newest = max(stamps)
        before = len(rows)
        rows = [r for r in rows if str(r.get("run_ts")) == newest]
        print(f"inventory: {len(stamps)} generations present, using the newest ({newest}): "
              f"{len(rows)} of {before} rows")

    keep, skipped_status = [], 0
    for row in rows:
        if str(row.get("cloud", conf.cloud)).lower() != conf.cloud:
            continue
        if not row.get("host") or not row.get("workspace_id"):
            continue
        # a workspace that is not RUNNING cannot be read; the inventory task records it, we exclude it
        status = str(row.get("workspace_status") or "RUNNING")
        if status != "RUNNING":
            skipped_status += 1
            continue
        keep.append(row)
    msg = f"inventory: {len(keep)} rows for cloud={conf.cloud}"
    if skipped_status:
        msg += f" ({skipped_status} excluded as not RUNNING)"
    print(msg)
    return keep


def fan_out(items: list[Any], worker: Callable[[Any], Any], in_flight: int) -> list[Any]:
    """Parallel ACROSS workspaces. Each worker is serial internally by construction."""
    from concurrent.futures import ThreadPoolExecutor, as_completed

    results: list[Any] = []
    if in_flight <= 1:
        for item in items:
            results.append(worker(item))
        return results
    with ThreadPoolExecutor(max_workers=in_flight) as pool:
        futures = {pool.submit(worker, item): item for item in items}
        for fut in as_completed(futures):
            results.append(fut.result())
    return results


def emit_summary(summary: dict) -> None:
    """Return a machine-readable summary from a job run.

    Without this a successful run says only "SUCCESS" — an operator running 700 workspaces needs the counts
    in the run record itself, not only in the driver log.
    """
    print("SUMMARY " + json.dumps(summary, default=str))
    dbu = _dbutils()
    if dbu is not None:
        try:
            dbu.notebook.exit(json.dumps(summary, default=str))
        except Exception:
            pass


def banner(conf: Conf, title: str) -> None:
    print("=" * 78)
    print(f"{title}  |  run_id={conf.run_id}  ts={conf.run_ts}")
    print(f"mode={conf.mode} cloud={conf.cloud} output={conf.output} in_flight={conf.workspaces_in_flight} "
          f"aad_detection={conf.aad_detection} migrated_workspaces={conf.migrated_workspaces}")
    if conf.migrated_workspaces == "clone_fallback":
        print("!! migrated_workspaces=clone_fallback — ALREADY-MIGRATED workspaces are IN SCOPE, gated on the")
        print("   migration clone group (what `users` held at migration). System groups are still never touched.")
    print("=" * 78)

#!/usr/bin/env python3
"""
extract_nifi_sources_1.12.py

Extract "source" processors from an Apache NiFi 1.12.1 instance through the
NiFi REST API and report:

  * ListSFTP processors            -> processor name + remote Hostname
  * SQL table-fetch processors     -> processor name + WHERE filter clause
    (QueryDatabaseTable, QueryDatabaseTableRecord, GenerateTableFetch)
  * InvokeHTTP processors          -> processor name + request URL

For every matched processor it also reports the parent process group name
and the processor UID.

AUTHENTICATION
--------------
This variant assumes NiFi sits behind HAProxy, which terminates simple
HTTP Basic authentication. There is therefore NO NiFi token exchange:
credentials are sent as an HTTP Basic 'Authorization' header on every
request, and HAProxy forwards to the (typically unsecured) NiFi behind it.

The flow-traversal endpoints and property keys are unchanged from later 1.x
releases, so only the auth mechanism differs from the 1.20.0 script.

Usage:
    python extract_nifi_sources_1.12.py --url https://nifi.example.com \
        --user admin --password secret

    # HAProxy allows anonymous access (no basic auth)
    python extract_nifi_sources_1.12.py --url http://localhost:8080

    # CSV instead of the grouped text report
    python extract_nifi_sources_1.12.py --url https://nifi.example.com \
        --user admin --password secret --format csv
"""

import argparse
import csv
import re
import sys

import requests
from requests.auth import HTTPBasicAuth
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# --- what counts as a "source" -----------------------------------------------

SFTP_TYPES = {
    "org.apache.nifi.processors.standard.ListSFTP",
}

# SQL "fetch" processors that expose an "Additional WHERE clause".
SQL_TYPES = {
    "org.apache.nifi.processors.standard.QueryDatabaseTable",
    "org.apache.nifi.processors.standard.QueryDatabaseTableRecord",
    "org.apache.nifi.processors.standard.GenerateTableFetch",
}

HTTP_TYPES = {
    "org.apache.nifi.processors.standard.InvokeHTTP",
}

# Property KEYS as they appear in NiFi's properties map (not the UI display name).
HOSTNAME_KEYS = ("Hostname",)
WHERE_KEYS = ("db-fetch-where-clause",)
# InvokeHTTP URL: "HTTP URL" since the 1.16 refactor; "Remote URL" on flows
# migrated from older versions (which is what NiFi 1.12.1 itself uses).
URL_KEYS = ("Remote URL", "HTTP URL")


def first_prop(props, keys):
    """Return the first non-None value among the candidate property keys."""
    for k in keys:
        if props.get(k) is not None:
            return props[k]
    return ""


# --- factory inference -------------------------------------------------------

# Site codes look like: 2 letters + a digit + one alphanumeric.
# Matches RO03, SR08, IE75, MX37, CH5F, CH15, ... (case-insensitive).
SITE_CODE_RE = re.compile(r"[A-Za-z]{2}\d[A-Za-z0-9]")
_SEP_RE = re.compile(r"[\s_\-/|.,:]+")

# City-name factories can't be inferred by shape, so we match a known set.
# Seeded with the given examples; extend at runtime with --extra-cities.
DEFAULT_CITIES = {
    "Mexicali", "Bucharest", "Wuhan", "Presov", "Pune",
}


def infer_factory(path, cities):
    """
    Infer the factory name from a process-group ancestry path (the whole tree
    from root down to the processor's group, not just the immediate parent).

    path   : list of group names, root first.
    cities : set of known city-name factories.

    Matching runs in order of confidence:
      1. a whole segment is exactly a site code or a known city;
      2. a word inside a decorated segment ("RO03 - SMT", "Bucharest Plant 2");
      3. a site code / city found as a substring anywhere in a segment.
    Site codes are matched case-insensitively and returned upper-cased.
    """
    city_lookup = {c.lower(): c for c in cities}

    def as_city(token):
        return city_lookup.get(token.lower())

    def as_code(token):
        return token.upper() if SITE_CODE_RE.fullmatch(token) else None

    # Pass 1: whole segment.
    for seg in path:
        seg = (seg or "").strip()
        if not seg:
            continue
        if (c := as_code(seg)):
            return c
        if (c := as_city(seg)):
            return c

    # Pass 2: word within a decorated segment.
    for seg in path:
        for word in _SEP_RE.split((seg or "").strip()):
            if not word:
                continue
            if (c := as_code(word)):
                return c
            if (c := as_city(word)):
                return c

    # Pass 3: substring anywhere (last resort).
    for seg in path:
        seg = seg or ""
        low = seg.lower()
        for c_low, c in city_lookup.items():
            if c_low in low:
                return c
        mo = re.search(r"\b[A-Za-z]{2}\d[A-Za-z0-9]\b", seg)
        if mo:
            return mo.group(0).upper()

    return ""


# --- NiFi API client (HTTP Basic auth, terminated by HAProxy) ----------------

class NiFiClient:
    def __init__(self, base_url, user=None, password=None, verify=False):
        self.api = base_url.rstrip("/") + "/nifi-api"
        self.s = requests.Session()
        self.s.verify = verify
        # HAProxy handles HTTP Basic auth; send it on every request.
        if user is not None and password is not None:
            self.s.auth = HTTPBasicAuth(user, password)

    def _get(self, path):
        r = self.s.get(f"{self.api}{path}")
        r.raise_for_status()
        return r.json()

    def root_id(self):
        return self._get("/flow/process-groups/root")["processGroupFlow"]["id"]

    def processors(self, pg_id=None, descent=None):
        """
        Yield (processor entity, parent group name, ancestry path).

        The ancestry path spans the whole tree from root down to the
        processor's own group. It is assembled from TWO sources and merged,
        so a factory name is found even if one source is empty:
          * the group's breadcrumb chain (root -> current), and
          * the child group names collected while descending.
        """
        if descent is None:
            descent = []
        if pg_id is None:
            pg_id = self.root_id()
        pgf = self._get(f"/flow/process-groups/{pg_id}")["processGroupFlow"]
        flow = pgf["flow"]

        crumb = self._breadcrumb_path(pgf)
        path = []
        for name in list(crumb) + list(descent):
            if name and name not in path:
                path.append(name)
        group_name = path[-1] if path else ""

        for proc in flow.get("processors", []):
            # Ignore disabled processors (state == "DISABLED").
            if (proc.get("component") or {}).get("state") == "DISABLED":
                continue
            yield proc, group_name, path
        for child in flow.get("processGroups", []):
            child_name = (child.get("component") or {}).get("name", "")
            yield from self.processors(child["id"], descent + [child_name])

    @staticmethod
    def _breadcrumb_path(pgf):
        """Flatten a processGroupFlow breadcrumb chain into [root, ..., current]."""
        names = []
        bc = pgf.get("breadcrumb")
        while bc:
            name = (bc.get("breadcrumb") or {}).get("name")
            if name:
                names.append(name)
            bc = bc.get("parentBreadcrumb")
        names.reverse()  # breadcrumb chains child -> parent; we want root first
        return names


# --- extraction --------------------------------------------------------------

def collect(client, cities, debug=False):
    sftp_rows, sql_rows, http_rows = [], [], []
    for proc, group_name, path in client.processors():
        comp = proc.get("component", {})
        ptype = comp.get("type", "")
        name = comp.get("name", "")
        uid = comp.get("id") or proc.get("id", "")
        props = (comp.get("config") or {}).get("properties") or {}
        factory = infer_factory(path, cities)

        if debug and ptype in (SFTP_TYPES | SQL_TYPES | HTTP_TYPES):
            print(f"[debug] {name!r} factory={factory!r} path={path}",
                  file=sys.stderr)

        if ptype in SFTP_TYPES:
            sftp_rows.append({
                "name": name,
                "type": ptype.rsplit(".", 1)[-1],
                "parent_group": group_name,
                "factory": factory,
                "uid": uid,
                "hostname": first_prop(props, HOSTNAME_KEYS),
            })
        elif ptype in SQL_TYPES:
            sql_rows.append({
                "name": name,
                "type": ptype.rsplit(".", 1)[-1],
                "parent_group": group_name,
                "factory": factory,
                "uid": uid,
                "where": first_prop(props, WHERE_KEYS),
            })
        elif ptype in HTTP_TYPES:
            http_rows.append({
                "name": name,
                "type": ptype.rsplit(".", 1)[-1],
                "parent_group": group_name,
                "factory": factory,
                "uid": uid,
                "url": first_prop(props, URL_KEYS),
            })
    return sftp_rows, sql_rows, http_rows


# --- output ------------------------------------------------------------------

def print_report(sftp_rows, sql_rows, http_rows):
    print(f"\n=== ListSFTP sources ({len(sftp_rows)}) ===")
    for r in sftp_rows:
        print(f"  {r['name']}")
        print(f"      factory: {r['factory'] or '(unknown)'}")
        print(f"      group  : {r['parent_group'] or '(root)'}")
        print(f"      uid    : {r['uid']}")
        print(f"      host   : {r['hostname'] or '(not set)'}")

    print(f"\n=== SQL sources ({len(sql_rows)}) ===")
    for r in sql_rows:
        print(f"  {r['name']}  [{r['type']}]")
        print(f"      factory: {r['factory'] or '(unknown)'}")
        print(f"      group  : {r['parent_group'] or '(root)'}")
        print(f"      uid    : {r['uid']}")
        print(f"      where  : {r['where'] or '(none)'}")

    print(f"\n=== InvokeHTTP sources ({len(http_rows)}) ===")
    for r in http_rows:
        print(f"  {r['name']}")
        print(f"      factory: {r['factory'] or '(unknown)'}")
        print(f"      group  : {r['parent_group'] or '(root)'}")
        print(f"      uid    : {r['uid']}")
        print(f"      url    : {r['url'] or '(not set)'}")


def print_csv(sftp_rows, sql_rows, http_rows):
    w = csv.writer(sys.stdout)
    w.writerow(["category", "name", "type", "parent_group", "factory", "uid",
                "detail_key", "detail_value"])
    for r in sftp_rows:
        w.writerow(["sftp", r["name"], r["type"], r["parent_group"],
                    r["factory"], r["uid"], "hostname", r["hostname"]])
    for r in sql_rows:
        w.writerow(["sql", r["name"], r["type"], r["parent_group"],
                    r["factory"], r["uid"], "where", r["where"]])
    for r in http_rows:
        w.writerow(["http", r["name"], r["type"], r["parent_group"],
                    r["factory"], r["uid"], "url", r["url"]])


def main():
    ap = argparse.ArgumentParser(
        description="Extract SQL/SFTP source processors from NiFi 1.12.1 "
                    "(HTTP Basic auth via HAProxy)")
    ap.add_argument("--url", required=True, help="Base URL, e.g. https://nifi.example.com")
    ap.add_argument("--user", help="HTTP Basic username (HAProxy)")
    ap.add_argument("--password", help="HTTP Basic password (HAProxy)")
    ap.add_argument("--verify", action="store_true", help="Verify TLS certificates")
    ap.add_argument("--format", choices=["text", "csv"], default="text")
    ap.add_argument("--extra-cities",
                    help="Comma-separated extra city-name factories to recognise, "
                         "e.g. 'Guadalajara,Timisoara'")
    ap.add_argument("--debug", action="store_true",
                    help="Print each matched processor's group path to stderr")
    args = ap.parse_args()

    cities = set(DEFAULT_CITIES)
    if args.extra_cities:
        cities.update(c.strip() for c in args.extra_cities.split(",") if c.strip())

    client = NiFiClient(args.url, args.user, args.password, verify=args.verify)
    try:
        sftp_rows, sql_rows, http_rows = collect(client, cities, debug=args.debug)
    except requests.HTTPError as e:
        # 401 here almost always means the HAProxy basic-auth credentials were
        # missing or wrong.
        sys.exit(f"NiFi API error: {e}")
    except requests.RequestException as e:
        sys.exit(f"Connection error: {e}")

    if args.format == "csv":
        print_csv(sftp_rows, sql_rows, http_rows)
    else:
        print_report(sftp_rows, sql_rows, http_rows)


if __name__ == "__main__":
    main()
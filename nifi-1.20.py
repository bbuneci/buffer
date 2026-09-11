#!/usr/bin/env python3
"""
extract_nifi_sources.py

Extract "source" processors from an Apache NiFi 1.20.0 instance through the
NiFi REST API and report:

  * ListSFTP processors            -> processor name + remote Hostname
  * SQL table-fetch processors     -> processor name + WHERE filter clause
    (QueryDatabaseTable, QueryDatabaseTableRecord, GenerateTableFetch)

The script walks every process group starting at the root, so processors
nested inside child groups are included too.

Usage:
    # secured instance (username/password -> bearer token)
    python extract_nifi_sources.py --url https://nifi.example.com:8443 \
        --user admin --password secret

    # unsecured instance
    python extract_nifi_sources.py --url http://localhost:8080

    # already have a token
    python extract_nifi_sources.py --url https://nifi:8443 --token eyJ...

    # CSV instead of the grouped text report
    python extract_nifi_sources.py --url http://localhost:8080 --format csv
"""

import argparse
import csv
import re
import sys

import requests
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

# Property KEYS as they appear in NiFi's properties map (not the UI display name).
HOSTNAME_KEYS = ("Hostname",)
WHERE_KEYS = ("db-fetch-where-clause",)


def first_prop(props, keys):
    """Return the first non-None value among the candidate property keys."""
    for k in keys:
        if props.get(k) is not None:
            return props[k]
    return ""


# --- factory inference -------------------------------------------------------

# Site codes look like: 2 letters + a digit + one alphanumeric.
# Matches RO03, SR08, IE75, MX37, CH5F, CH15, ...
SITE_CODE_RE = re.compile(r"^[A-Z]{2}\d[A-Z0-9]$")

# City-name factories can't be inferred by shape, so we match a known set.
# Seeded with the given examples; extend at runtime with --extra-cities.
DEFAULT_CITIES = {
    "Mexicali", "Bucharest", "Wuhan", "Presov", "Pune",
}


def infer_factory(path, cities):
    """
    Infer the factory name from a process-group ancestry path.

    path   : list of group names from the top of the tree (root's direct
             child) down to the processor's immediate group. Root excluded.
    cities : set of known city-name factories.

    Strategy: scan the path from the top of the tree downward (factories
    normally sit high in the hierarchy) and return the first segment that
    either matches the site-code pattern or is a known city. A second pass
    also checks individual words within a segment, so decorated names like
    "RO03 - SMT Line" or "Bucharest Plant 2" still resolve.
    """
    city_lookup = {c.lower(): c for c in cities}

    # Pass 1: whole segment is the factory.
    for seg in path:
        token = seg.strip()
        if SITE_CODE_RE.match(token):
            return token
        if token.lower() in city_lookup:
            return city_lookup[token.lower()]

    # Pass 2: factory appears as a word inside a decorated segment name.
    for seg in path:
        for word in re.split(r"[\s_\-/|]+", seg.strip()):
            if SITE_CODE_RE.match(word):
                return word
            if word.lower() in city_lookup:
                return city_lookup[word.lower()]

    return ""


# --- NiFi API client ---------------------------------------------------------

class NiFiClient:
    def __init__(self, base_url, user=None, password=None, token=None, verify=False):
        self.api = base_url.rstrip("/") + "/nifi-api"
        self.s = requests.Session()
        self.s.verify = verify
        if token:
            self.s.headers["Authorization"] = f"Bearer {token}"
        elif user and password:
            self._login(user, password)

    def _login(self, user, password):
        r = self.s.post(f"{self.api}/access/token",
                        data={"username": user, "password": password})
        r.raise_for_status()
        self.s.headers["Authorization"] = f"Bearer {r.text}"

    def _get(self, path):
        r = self.s.get(f"{self.api}{path}")
        r.raise_for_status()
        return r.json()

    def root_id(self):
        return self._get("/flow/process-groups/root")["processGroupFlow"]["id"]

    def processors(self, pg_id=None):
        """
        Yield (processor entity, parent group name, ancestry path).

        `path` is the full list of group names from root down to and
        including the processor's own group, derived from the group's
        breadcrumb chain so it does not depend on child component names or
        on read permissions of intermediate groups.
        """
        if pg_id is None:
            pg_id = self.root_id()
        pgf = self._get(f"/flow/process-groups/{pg_id}")["processGroupFlow"]
        flow = pgf["flow"]
        path = self._breadcrumb_path(pgf)
        group_name = path[-1] if path else ""
        for proc in flow.get("processors", []):
            # Ignore disabled processors (state == "DISABLED").
            if (proc.get("component") or {}).get("state") == "DISABLED":
                continue
            yield proc, group_name, path
        for child in flow.get("processGroups", []):
            yield from self.processors(child["id"])

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

def collect(client, cities):
    sftp_rows, sql_rows = [], []
    for proc, group_name, path in client.processors():
        comp = proc.get("component", {})
        ptype = comp.get("type", "")
        name = comp.get("name", "")
        uid = comp.get("id") or proc.get("id", "")
        props = (comp.get("config") or {}).get("properties") or {}
        factory = infer_factory(path, cities)

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
    return sftp_rows, sql_rows


# --- output ------------------------------------------------------------------

def print_report(sftp_rows, sql_rows):
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


def print_csv(sftp_rows, sql_rows):
    w = csv.writer(sys.stdout)
    w.writerow(["category", "name", "type", "parent_group", "factory", "uid",
                "detail_key", "detail_value"])
    for r in sftp_rows:
        w.writerow(["sftp", r["name"], r["type"], r["parent_group"],
                    r["factory"], r["uid"], "hostname", r["hostname"]])
    for r in sql_rows:
        w.writerow(["sql", r["name"], r["type"], r["parent_group"],
                    r["factory"], r["uid"], "where", r["where"]])


def main():
    ap = argparse.ArgumentParser(
        description="Extract SQL/SFTP source processors from NiFi 1.20.0")
    ap.add_argument("--url", required=True, help="NiFi base URL, e.g. https://host:8443")
    ap.add_argument("--user")
    ap.add_argument("--password")
    ap.add_argument("--token", help="Existing bearer token (skips login)")
    ap.add_argument("--verify", action="store_true", help="Verify TLS certificates")
    ap.add_argument("--format", choices=["text", "csv"], default="text")
    ap.add_argument("--extra-cities",
                    help="Comma-separated extra city-name factories to recognise, "
                         "e.g. 'Guadalajara,Timisoara'")
    args = ap.parse_args()

    cities = set(DEFAULT_CITIES)
    if args.extra_cities:
        cities.update(c.strip() for c in args.extra_cities.split(",") if c.strip())

    client = NiFiClient(args.url, args.user, args.password, args.token,
                        verify=args.verify)
    try:
        sftp_rows, sql_rows = collect(client, cities)
    except requests.HTTPError as e:
        sys.exit(f"NiFi API error: {e}")
    except requests.RequestException as e:
        sys.exit(f"Connection error: {e}")

    if args.format == "csv":
        print_csv(sftp_rows, sql_rows)
    else:
        print_report(sftp_rows, sql_rows)


if __name__ == "__main__":
    main()
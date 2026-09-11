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
        """Yield (processor entity, parent group name), recursing nested groups."""
        if pg_id is None:
            pg_id = self.root_id()
        pgf = self._get(f"/flow/process-groups/{pg_id}")["processGroupFlow"]
        group_name = pgf.get("breadcrumb", {}).get("breadcrumb", {}).get("name", "")
        flow = pgf["flow"]
        for proc in flow.get("processors", []):
            yield proc, group_name
        for child in flow.get("processGroups", []):
            yield from self.processors(child["id"])


# --- extraction --------------------------------------------------------------

def collect(client):
    sftp_rows, sql_rows = [], []
    for proc, group_name in client.processors():
        comp = proc.get("component", {})
        ptype = comp.get("type", "")
        name = comp.get("name", "")
        uid = comp.get("id") or proc.get("id", "")
        props = (comp.get("config") or {}).get("properties") or {}

        if ptype in SFTP_TYPES:
            sftp_rows.append({
                "name": name,
                "type": ptype.rsplit(".", 1)[-1],
                "parent_group": group_name,
                "uid": uid,
                "hostname": first_prop(props, HOSTNAME_KEYS),
            })
        elif ptype in SQL_TYPES:
            sql_rows.append({
                "name": name,
                "type": ptype.rsplit(".", 1)[-1],
                "parent_group": group_name,
                "uid": uid,
                "where": first_prop(props, WHERE_KEYS),
            })
    return sftp_rows, sql_rows


# --- output ------------------------------------------------------------------

def print_report(sftp_rows, sql_rows):
    print(f"\n=== ListSFTP sources ({len(sftp_rows)}) ===")
    for r in sftp_rows:
        print(f"  {r['name']}")
        print(f"      group: {r['parent_group'] or '(root)'}")
        print(f"      uid  : {r['uid']}")
        print(f"      host : {r['hostname'] or '(not set)'}")

    print(f"\n=== SQL sources ({len(sql_rows)}) ===")
    for r in sql_rows:
        print(f"  {r['name']}  [{r['type']}]")
        print(f"      group: {r['parent_group'] or '(root)'}")
        print(f"      uid  : {r['uid']}")
        print(f"      where: {r['where'] or '(none)'}")


def print_csv(sftp_rows, sql_rows):
    w = csv.writer(sys.stdout)
    w.writerow(["category", "name", "type", "parent_group", "uid",
                "detail_key", "detail_value"])
    for r in sftp_rows:
        w.writerow(["sftp", r["name"], r["type"], r["parent_group"], r["uid"],
                    "hostname", r["hostname"]])
    for r in sql_rows:
        w.writerow(["sql", r["name"], r["type"], r["parent_group"], r["uid"],
                    "where", r["where"]])


def main():
    ap = argparse.ArgumentParser(
        description="Extract SQL/SFTP source processors from NiFi 1.20.0")
    ap.add_argument("--url", required=True, help="NiFi base URL, e.g. https://host:8443")
    ap.add_argument("--user")
    ap.add_argument("--password")
    ap.add_argument("--token", help="Existing bearer token (skips login)")
    ap.add_argument("--verify", action="store_true", help="Verify TLS certificates")
    ap.add_argument("--format", choices=["text", "csv"], default="text")
    args = ap.parse_args()

    client = NiFiClient(args.url, args.user, args.password, args.token,
                        verify=args.verify)
    try:
        sftp_rows, sql_rows = collect(client)
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
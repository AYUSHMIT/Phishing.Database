#!/usr/bin/env python3
"""
Enrich domains with registrar information using RDAP/WHOIS.

This script takes a CSV of domains and enriches them with registrar data
by querying RDAP servers (via IANA bootstrap) and falling back to WHOIS.
"""
import argparse
import json
import time
from pathlib import Path

import pandas as pd
import requests

# Optional WHOIS dependency
try:
    import whois
    HAS_WHOIS = True
except ImportError:
    HAS_WHOIS = False


BOOTSTRAP_URL = "https://data.iana.org/rdap/dns.json"
SESSION = requests.Session()
SESSION.headers.update({"User-Agent": "AYUSHMIT-phishing-research/1.0"})


def load_bootstrap():
    """Load IANA RDAP bootstrap data to map TLDs to RDAP servers."""
    try:
        r = SESSION.get(BOOTSTRAP_URL, timeout=20)
        r.raise_for_status()
        data = r.json()
        
        # Map TLD -> list of RDAP servers
        mapping = {}
        for service in data.get("services", []):
            tlds = service[0]
            servers = service[1]
            for tld in tlds:
                mapping[tld.lower()] = servers
        
        return mapping
    except Exception as e:
        print(f"Warning: Could not load RDAP bootstrap: {e}")
        return {}


def rdap_endpoints_for_tld(tld: str, servers: list):
    """Generate possible RDAP endpoint URLs for a TLD."""
    for base in servers:
        base = base.rstrip("/")
        # Try common domain endpoints
        yield f"{base}/domain/"
        yield f"{base}/rdap/domain/"
        yield f"{base}/domains/"
        yield base + "/"


def parse_registrar_from_rdap(obj: dict):
    """Extract registrar name from RDAP response object."""
    # Prefer top-level 'registrar' field if present
    if "registrar" in obj and isinstance(obj["registrar"], str):
        return obj["registrar"].strip()
    
    # Otherwise scan entities for role 'registrar'
    for ent in obj.get("entities", []):
        roles = [r.lower() for r in ent.get("roles", [])]
        if "registrar" in roles:
            # Name extraction via vcardArray
            vcard = ent.get("vcardArray")
            if isinstance(vcard, list) and len(vcard) == 2:
                for item in vcard[1]:
                    if item and item[0] in ("fn", "org") and len(item) > 3:
                        name = item[3]
                        if isinstance(name, str) and name.strip():
                            return name.strip()
            
            # Fallback to 'handle' or 'name'
            for key in ("handle", "name"):
                if ent.get(key):
                    return str(ent[key]).strip()
    
    return None


def whois_registrar(domain: str):
    """Query WHOIS for registrar information (fallback method)."""
    if not HAS_WHOIS:
        return None
    
    try:
        w = whois.whois(domain)
        reg = w.registrar
        
        if isinstance(reg, (list, tuple)) and reg:
            reg = reg[0]
        
        if reg and isinstance(reg, str) and reg.strip():
            return reg.strip()
    except Exception:
        pass
    
    return None


def query_rdap(domain: str, bootstrap: dict, sleep_s: float):
    """Query RDAP for domain registrar information."""
    tld = domain.split(".")[-1].lower()
    servers = bootstrap.get(tld)
    
    if not servers:
        return None
    
    for ep in rdap_endpoints_for_tld(tld, servers):
        try:
            r = SESSION.get(ep + domain, timeout=20)
            
            if r.status_code == 200:
                content_type = r.headers.get("Content-Type", "")
                if "application/json" in content_type or "application/rdap+json" in content_type:
                    obj = r.json()
                    registrar = parse_registrar_from_rdap(obj)
                    if registrar:
                        return registrar
            
            elif r.status_code in (301, 302, 303, 307, 308):
                # Follow redirect once
                location = r.headers.get("Location")
                if location:
                    r2 = SESSION.get(location, timeout=20)
                    if r2.status_code == 200:
                        obj = r2.json()
                        registrar = parse_registrar_from_rdap(obj)
                        if registrar:
                            return registrar
        
        except Exception:
            continue
        finally:
            time.sleep(sleep_s)
    
    return None


def enrich(df_in: pd.DataFrame, sleep_s: float = 0.5, use_whois: bool = True):
    """Enrich domains with registrar information."""
    print("Loading RDAP bootstrap data...")
    bootstrap = load_bootstrap()
    print(f"Loaded RDAP servers for {len(bootstrap)} TLDs")
    
    rows = []
    total = len(df_in)
    
    for idx, (_, row) in enumerate(df_in.iterrows(), 1):
        rd = row["registrable_domain"]
        
        if idx % 100 == 0 or idx == 1:
            print(f"Processing {idx}/{total}: {rd}")
        
        registrar = None
        
        # Try RDAP first
        registrar = query_rdap(rd, bootstrap, sleep_s)
        
        # Fall back to WHOIS if enabled and RDAP failed
        if not registrar and use_whois:
            registrar = whois_registrar(rd)
        
        rows.append({
            "registrable_domain": rd,
            "source_type": row["source_type"],
            "source_file": row["source_file"],
            "registrar": registrar or "UNKNOWN"
        })
    
    return pd.DataFrame(rows)


def main():
    ap = argparse.ArgumentParser(
        description="Enrich domains with registrar information via RDAP/WHOIS"
    )
    ap.add_argument(
        "--domains-csv",
        type=str,
        default="domains.csv",
        help="Input CSV file with domains (default: domains.csv)"
    )
    ap.add_argument(
        "--out",
        type=str,
        default="domains_with_registrar.csv",
        help="Output CSV file (default: domains_with_registrar.csv)"
    )
    ap.add_argument(
        "--sleep",
        type=float,
        default=0.5,
        help="Delay between RDAP requests in seconds (default: 0.5)"
    )
    ap.add_argument(
        "--no-whois",
        action="store_true",
        help="Disable WHOIS fallback (RDAP only)"
    )
    args = ap.parse_args()

    print(f"Reading domains from {args.domains_csv}...")
    df = pd.read_csv(args.domains_csv)
    print(f"Loaded {len(df)} domains")
    
    enriched = enrich(df, sleep_s=args.sleep, use_whois=not args.no_whois)
    
    enriched.to_csv(args.out, index=False)
    print(f"\nEnriched {len(enriched)} domains -> {args.out}")
    
    # Print summary
    unknown_count = (enriched["registrar"] == "UNKNOWN").sum()
    known_count = len(enriched) - unknown_count
    print(f"\nSummary:")
    print(f"  Known registrars: {known_count} ({100*known_count/len(enriched):.1f}%)")
    print(f"  Unknown: {unknown_count} ({100*unknown_count/len(enriched):.1f}%)")


if __name__ == "__main__":
    main()

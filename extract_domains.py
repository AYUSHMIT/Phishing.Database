#!/usr/bin/env python3
"""
Extract domains from phishing database files.

This script extracts domains from the Phishing.Database repository files
and normalizes them to registrable domains for registrar analysis.
"""
import argparse
import os
from pathlib import Path
from urllib.parse import urlparse

import pandas as pd
import tldextract


def parse_line(s: str):
    """Parse a line from a data file, removing comments and whitespace."""
    s = s.split("#", 1)[0].strip()
    return s if s else None


def extract_domains_from_file(filepath: Path, source_type: str):
    """Extract domains from a single file."""
    rows = []
    try:
        with open(filepath, encoding="utf-8", errors="ignore") as f:
            for raw in f:
                line = parse_line(raw)
                if not line:
                    continue
                
                if source_type == "domains":
                    # Direct domain file
                    dom = line.lower().strip(".")
                    rows.append({
                        "domain": dom,
                        "source_file": str(filepath.name),
                        "source_type": source_type
                    })
                elif source_type == "links":
                    # Extract hostname from URL
                    try:
                        parsed = urlparse(line)
                        host = parsed.hostname
                        if host:
                            rows.append({
                                "domain": host.lower(),
                                "source_file": str(filepath.name),
                                "source_type": source_type
                            })
                    except Exception:
                        continue
    except Exception as e:
        print(f"Warning: Could not process {filepath}: {e}")
    
    return rows


def walk_repo(root: Path, include_links: bool, status_filter: str):
    """Walk repository and extract domains from matching files."""
    rows = []
    
    # Find domain files
    domain_patterns = [
        f"phishing-domains-{status_filter}.txt" if status_filter != "all" else "phishing-domains-*.txt"
    ]
    
    for pattern in domain_patterns:
        if "*" in pattern:
            # Use glob for wildcard patterns
            for fp in root.glob(pattern):
                if fp.is_file():
                    rows.extend(extract_domains_from_file(fp, "domains"))
        else:
            # Direct file path
            fp = root / pattern
            if fp.exists() and fp.is_file():
                rows.extend(extract_domains_from_file(fp, "domains"))
    
    # Find link files if requested
    if include_links:
        link_patterns = [
            f"phishing-links-{status_filter}.txt" if status_filter != "all" else "phishing-links-*.txt"
        ]
        
        for pattern in link_patterns:
            if "*" in pattern:
                for fp in root.glob(pattern):
                    if fp.is_file():
                        rows.extend(extract_domains_from_file(fp, "links"))
            else:
                fp = root / pattern
                if fp.exists() and fp.is_file():
                    rows.extend(extract_domains_from_file(fp, "links"))
    
    df = pd.DataFrame(rows).dropna()
    
    if df.empty:
        return df
    
    # Normalize to registrable domain (SLD+TLD) to align with registrar granularity
    def registrable(d):
        ext = tldextract.extract(d)
        if not ext.suffix:
            return None
        rd = ".".join([ext.domain, ext.suffix]) if ext.domain else ext.suffix
        return rd.lower()
    
    df["registrable_domain"] = df["domain"].map(registrable)
    df = df.dropna(subset=["registrable_domain"]).drop_duplicates(subset=["registrable_domain", "source_type"])
    
    return df


def main():
    ap = argparse.ArgumentParser(
        description="Extract domains from Phishing.Database files for registrar analysis"
    )
    ap.add_argument(
        "--root",
        type=str,
        default=".",
        help="Path to Phishing.Database repository root (default: current directory)"
    )
    ap.add_argument(
        "--include-links",
        action="store_true",
        help="Include hostnames extracted from phishing-links-*.txt files"
    )
    ap.add_argument(
        "--status",
        type=str,
        choices=["ACTIVE", "INACTIVE", "INVALID", "all"],
        default="ACTIVE",
        help="Filter by status (default: ACTIVE)"
    )
    ap.add_argument(
        "--out",
        type=str,
        default="domains.csv",
        help="Output CSV file (default: domains.csv)"
    )
    ap.add_argument(
        "--limit",
        type=int,
        default=None,
        help="Limit number of domains to extract (useful for testing)"
    )
    args = ap.parse_args()

    print(f"Extracting domains from {args.root}...")
    print(f"Status filter: {args.status}")
    print(f"Include links: {args.include_links}")
    
    df = walk_repo(Path(args.root), args.include_links, args.status)
    
    if df.empty:
        print("No domains found!")
        return
    
    # Apply limit if specified
    if args.limit:
        df = df.head(args.limit)
        print(f"Limited to {args.limit} domains")
    
    df.to_csv(args.out, index=False)
    print(f"Wrote {len(df)} rows to {args.out}")
    print(f"\nSummary:")
    print(f"  Unique registrable domains: {df['registrable_domain'].nunique()}")
    print(f"  Source types: {df['source_type'].value_counts().to_dict()}")


if __name__ == "__main__":
    main()

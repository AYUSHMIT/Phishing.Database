#!/usr/bin/env python3
"""
Aggregate and rank registrars by phishing domain count.

This script takes enriched domain data and produces a ranked list
of registrars by the number of phishing domains registered with them.
"""
import argparse
import pandas as pd


def main():
    ap = argparse.ArgumentParser(
        description="Aggregate and rank registrars by phishing domain count"
    )
    ap.add_argument(
        "--in",
        dest="inp",
        type=str,
        default="domains_with_registrar.csv",
        help="Input CSV file with registrar data (default: domains_with_registrar.csv)"
    )
    ap.add_argument(
        "--top",
        type=int,
        default=25,
        help="Number of top registrars to display (default: 25)"
    )
    ap.add_argument(
        "--out",
        type=str,
        default="registrar_rankings.csv",
        help="Output CSV file (default: registrar_rankings.csv)"
    )
    ap.add_argument(
        "--by",
        type=str,
        choices=["overall", "from_domains", "from_links"],
        default="overall",
        help="Filter data before aggregation (default: overall)"
    )
    ap.add_argument(
        "--exclude-unknown",
        action="store_true",
        help="Exclude UNKNOWN registrars from rankings"
    )
    args = ap.parse_args()

    print(f"Reading enriched data from {args.inp}...")
    df = pd.read_csv(args.inp)
    print(f"Loaded {len(df)} records")
    
    # Apply filters
    if args.by == "from_domains":
        df = df[df["source_type"] == "domains"]
        print(f"Filtered to domains only: {len(df)} records")
    elif args.by == "from_links":
        df = df[df["source_type"] == "links"]
        print(f"Filtered to links only: {len(df)} records")
    
    # Exclude UNKNOWN if requested
    if args.exclude_unknown:
        df = df[df["registrar"] != "UNKNOWN"]
        print(f"Excluded UNKNOWN: {len(df)} records remaining")
    
    # Group and rank
    ranks = (
        df.groupby("registrar")
        .size()
        .reset_index(name="count")
        .sort_values("count", ascending=False)
    )
    
    # Add percentage
    total = ranks["count"].sum()
    ranks["percentage"] = (ranks["count"] / total * 100).round(2)
    
    # Save full rankings
    ranks.to_csv(args.out, index=False)
    
    # Display top N
    print(f"\n{'='*70}")
    print(f"Top {args.top} Registrars (by phishing domain count)")
    print(f"{'='*70}")
    print(ranks.head(args.top).to_string(index=False))
    print(f"{'='*70}")
    print(f"\nFull rankings saved to {args.out}")
    print(f"Total unique registrars: {len(ranks)}")
    print(f"Total domains analyzed: {total}")


if __name__ == "__main__":
    main()

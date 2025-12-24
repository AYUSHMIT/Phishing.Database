#!/bin/bash
# Example usage of the registrar analysis pipeline
# This script demonstrates how to run the complete pipeline

set -e  # Exit on error

echo "=========================================="
echo "Registrar Analysis Pipeline Example"
echo "=========================================="
echo ""

# Configuration
LIMIT="${1:-100}"  # Default to 100 domains, or use first argument
STATUS="${2:-ACTIVE}"  # Default to ACTIVE, or use second argument

echo "Configuration:"
echo "  Domain limit: $LIMIT"
echo "  Status filter: $STATUS"
echo ""

# Step 1: Extract domains
echo "Step 1/3: Extracting domains..."
python3 extract_domains.py \
    --status "$STATUS" \
    --limit "$LIMIT" \
    --out domains.csv
echo ""

# Step 2: Enrich with registrar data
echo "Step 2/3: Enriching with registrar data..."
echo "  (This may take a while depending on domain count)"
python3 enrich_registrars.py \
    --domains-csv domains.csv \
    --out domains_with_registrar.csv \
    --sleep 0.5
echo ""

# Step 3: Aggregate and rank
echo "Step 3/3: Generating registrar rankings..."
python3 aggregate_registrars.py \
    --in domains_with_registrar.csv \
    --top 25 \
    --out registrar_rankings.csv
echo ""

echo "=========================================="
echo "Pipeline complete!"
echo "=========================================="
echo ""
echo "Output files:"
echo "  domains.csv - Extracted domains"
echo "  domains_with_registrar.csv - Enriched with registrar data"
echo "  registrar_rankings.csv - Ranked registrars"
echo ""
echo "To view top 10 registrars:"
echo "  head -11 registrar_rankings.csv"

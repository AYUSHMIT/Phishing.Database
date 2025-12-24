# Registrar Analysis Pipeline

This directory contains tools to analyze which domain registrars are most frequently associated with phishing domains in the Phishing.Database.

## Overview

The pipeline consists of three Python scripts that work together to:

1. **Extract domains** from the phishing database files
2. **Enrich domains** with registrar information via RDAP/WHOIS queries
3. **Aggregate and rank** registrars by phishing domain count

## Prerequisites

- Python 3.7 or higher
- Internet connection for RDAP/WHOIS queries

## Installation

1. Clone this repository (if not already done)
2. Create a virtual environment and install dependencies:

```bash
python3 -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

## Quick Start

**Recommended:** Analyze ACTIVE domains only (fastest, most relevant):

```bash
# Extract domains (limited to 100 for testing)
python3 extract_domains.py --status ACTIVE --limit 100 --out domains.csv

# Enrich with registrar data
python3 enrich_registrars.py --domains-csv domains.csv --out domains_with_registrar.csv

# Generate rankings
python3 aggregate_registrars.py --in domains_with_registrar.csv --top 25 --out registrar_rankings.csv
```

## Usage

### Step 1: Extract Domains

Extract domains from phishing database files and normalize them to registrable domains (SLD+TLD).

```bash
python3 extract_domains.py [OPTIONS]
```

**Options:**
- `--root PATH` - Path to repository root (default: current directory)
- `--status {ACTIVE,INACTIVE,INVALID,all}` - Filter by status (default: ACTIVE)
- `--include-links` - Also extract hostnames from phishing-links-*.txt files
- `--limit N` - Limit number of domains (useful for testing)
- `--out FILE` - Output CSV file (default: domains.csv)

**Examples:**

```bash
# Extract only ACTIVE domains
python3 extract_domains.py --status ACTIVE --out active_domains.csv

# Extract all domains including from links
python3 extract_domains.py --status all --include-links --out all_domains.csv

# Test with small sample
python3 extract_domains.py --limit 50 --out test_domains.csv
```

### Step 2: Enrich with Registrar Data

Query RDAP servers (via IANA bootstrap) to find registrar information for each domain. Falls back to WHOIS if RDAP is unavailable.

```bash
python3 enrich_registrars.py [OPTIONS]
```

**Options:**
- `--domains-csv FILE` - Input CSV from extract_domains.py (default: domains.csv)
- `--out FILE` - Output CSV file (default: domains_with_registrar.csv)
- `--sleep SECONDS` - Delay between RDAP requests (default: 0.5)
- `--no-whois` - Disable WHOIS fallback (RDAP only)

**Examples:**

```bash
# Standard enrichment
python3 enrich_registrars.py --domains-csv domains.csv --out enriched.csv

# Faster querying (be respectful to servers!)
python3 enrich_registrars.py --sleep 0.2 --out enriched.csv

# RDAP only, no WHOIS fallback
python3 enrich_registrars.py --no-whois --out enriched.csv
```

**Note:** This step can be time-consuming for large datasets due to rate limiting. Consider:
- Starting with a small `--limit` in step 1 for testing
- Increasing `--sleep` if you encounter rate limiting
- Running during off-peak hours for large analyses

### Step 3: Aggregate and Rank

Generate a ranked list of registrars by phishing domain count.

```bash
python3 aggregate_registrars.py [OPTIONS]
```

**Options:**
- `--in FILE` - Input CSV from enrich_registrars.py (default: domains_with_registrar.csv)
- `--out FILE` - Output CSV file (default: registrar_rankings.csv)
- `--top N` - Number of top registrars to display (default: 25)
- `--by {overall,from_domains,from_links}` - Filter before aggregation (default: overall)
- `--exclude-unknown` - Exclude UNKNOWN registrars from rankings

**Examples:**

```bash
# Top 25 registrars
python3 aggregate_registrars.py --in enriched.csv --top 25

# Top 50, excluding unknown
python3 aggregate_registrars.py --top 50 --exclude-unknown

# Rank only domains (not from links)
python3 aggregate_registrars.py --by from_domains --top 30
```

## Output Files

### domains.csv
Extracted and normalized domains with metadata:
- `domain` - Original domain/hostname
- `registrable_domain` - Normalized registrable domain (SLD+TLD)
- `source_file` - Source file name
- `source_type` - Either "domains" or "links"

### domains_with_registrar.csv
Enriched domains with registrar information:
- `registrable_domain` - Normalized domain
- `source_type` - "domains" or "links"
- `source_file` - Source file name
- `registrar` - Registrar name or "UNKNOWN"

### registrar_rankings.csv
Ranked registrars:
- `registrar` - Registrar name
- `count` - Number of phishing domains
- `percentage` - Percentage of total domains

## Tips and Best Practices

### Performance

- **Start small:** Use `--limit` flag when testing to avoid long wait times
- **Focus on ACTIVE:** Use `--status ACTIVE` for most relevant, current data
- **Be respectful:** Keep reasonable `--sleep` delays to avoid overwhelming RDAP/WHOIS servers
- **Cache results:** Save intermediate CSVs to avoid re-querying

### Interpretation

- **"Most implicated" ≠ negligent:** High counts may indicate:
  - Large market share (popular registrars have more domains)
  - Targets of opportunity (attackers prefer certain registrars)
  - Quick takedown response (domains detected before removal)
  
- **Consider context:**
  - Compare against registrar market share
  - Look at trends over time
  - Analyze takedown response times (requires temporal data)

### RDAP/WHOIS Coverage

- **RDAP coverage varies by TLD:** Some TLDs have excellent RDAP support, others don't
- **WHOIS fallback:** Provides broader coverage but can be rate-limited or redacted
- **Expect some UNKNOWNs:** Privacy protection, rate limiting, or missing data will result in UNKNOWN registrars

## Advanced Usage

### Time-Based Analysis

To analyze trends over time, you would need historical snapshots. The current repository only has the latest data. For temporal analysis:

1. Use archived snapshots from [Phishing-Database/frozen-datasets](https://github.com/Phishing-Database/frozen-datasets)
2. Run the pipeline on each snapshot
3. Compare rankings across time periods

### Custom Filtering

The scripts output CSV files that can be further analyzed with pandas, Excel, or other tools:

```python
import pandas as pd

# Load enriched data
df = pd.read_csv('domains_with_registrar.csv')

# Filter to specific TLD
df_com = df[df['registrable_domain'].str.endswith('.com')]

# Custom aggregation
registrar_by_tld = df.groupby(['registrar', 'source_type']).size()
```

## Troubleshooting

### "No domains found!"
- Check that you're running from the repository root
- Verify the status filter matches available files
- Ensure data files are not empty

### Rate Limiting / Timeouts
- Increase `--sleep` delay
- Use `--no-whois` to skip WHOIS queries
- Split large datasets into smaller batches

### Import Errors
- Ensure virtual environment is activated
- Run `pip install -r requirements.txt`
- Check Python version (3.7+ required)

## Contributing

Improvements and suggestions are welcome! Areas for enhancement:
- Parallel RDAP queries (with proper rate limiting)
- Better registrar name normalization
- Integration with frozen-datasets for temporal analysis
- Support for additional data sources

## License

This pipeline is part of the Phishing.Database project and follows the same license.

## Disclaimer

This tool is for research and threat intelligence purposes. "Most implicated" refers to frequency in the dataset and does not imply registrar negligence. Many factors affect these numbers including market share, takedown response time, and attacker preferences.

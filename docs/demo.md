# Demo Walkthrough

## Skenario
Deteksi Application Shimming (MITRE T1546.011).

## Jalankan

    python -m cli investigate --events examples/application_shimming.json --title 'Application Shimming' --format markdown --ai

## Hasil

    Risk Score: 45/100
    Confidence: 0.54
    Priority: CRITICAL

    Breakdown:
      evidence: +40.0
      correlation: +3.3
      hypothesis: +13.8
      penalty: -12.0

## Hypotheses

MAIN - Possible persistence via Application Shimming
- Status: supported, confidence 0.55
- MITRE: T1546.011

COUNTER - Legitimate Windows compatibility activity

SUB - Correlated event cluster indicates single activity

## Format Output

- markdown - full report
- json - structured
- text - executive summary

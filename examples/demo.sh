#!/bin/bash

# Simple demo script for the dependency-risk-profiler

# Make sure we're in the examples directory
cd "$(dirname "$0")"

echo "===== Dependency Risk Profiler Demo ====="
echo ""

echo "1. Analyzing Python dependencies in requirements.txt"
echo "---------------------------------------------"
python -m dependency_risk_profiler.cli.main --manifest requirements.txt
echo ""

echo "2. Analyzing Node.js dependencies in package-lock.json"
echo "---------------------------------------------------"
python -m dependency_risk_profiler.cli.main --manifest package-lock.json
echo ""

echo "3. Analyzing Go dependencies in go.mod"
echo "-----------------------------------"
python -m dependency_risk_profiler.cli.main --manifest go.mod
echo ""

echo "4. Output in JSON format"
echo "---------------------"
python -m dependency_risk_profiler.cli.main --manifest requirements.txt --output json
echo ""

echo "5. Custom Risk Weights (Basic)"
echo "--------------------------"
python -m dependency_risk_profiler.cli.main --manifest requirements.txt \
  --staleness-weight 0.4 \
  --maintainer-weight 0.2 \
  --deprecation-weight 0.3 \
  --exploit-weight 0.6 \
  --version-weight 0.3 \
  --health-weight 0.1

echo ""
echo "6. Custom Risk Weights (Enhanced)"
echo "-------------------------------"
python -m dependency_risk_profiler.cli.main --manifest requirements.txt \
  --license-weight 0.4 \
  --community-weight 0.3 \
  --transitive-weight 0.2
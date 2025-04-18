#!/bin/bash
# Script to install OpenSSF Allstar for GitHub repositories
# Note: This script provides guidance but requires manual steps for app installation

echo "OpenSSF Allstar Installation Guide"
echo "=================================="
echo ""
echo "Follow these steps to install Allstar for your GitHub repository:"
echo ""
echo "1. Visit https://github.com/apps/allstar-app and install the app for your organization or repository"
echo "   - You can choose specific repositories or all repositories"
echo ""
echo "2. Verify that the Allstar configuration exists in your repository:"
echo "   - Your repository should have the following directory: .github/allstar/"
echo "   - The following files should exist:"
echo "     - .github/allstar/allstar.yaml (main configuration)"
echo "     - .github/allstar/branch_protection.yaml"
echo "     - .github/allstar/binary_artifacts.yaml"
echo "     - .github/allstar/outside.yaml"
echo "     - .github/allstar/scorecard.yaml"
echo "     - .github/allstar/security.yaml"
echo ""
echo "3. Wait for Allstar to scan your repository (this may take a few minutes)"
echo ""
echo "4. Check for any issues created by Allstar in your repository's Issues tab"
echo ""
echo "5. For more information, visit: https://github.com/ossf/allstar"
echo ""
echo "Note: This script is a guide only and does not perform the actual installation."
echo "      Allstar is installed as a GitHub App at the organization or repository level."

# Make the script executable
chmod +x "$0"
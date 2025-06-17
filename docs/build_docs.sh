#!/bin/bash
# Build documentation locally

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${YELLOW}Building Intellicrack Documentation...${NC}"

# Check if sphinx is installed
if ! command -v sphinx-build &> /dev/null; then
    echo -e "${RED}Sphinx not found. Installing documentation dependencies...${NC}"
    pip install -r docs/requirements.txt
fi

# Clean previous builds
echo -e "${YELLOW}Cleaning previous builds...${NC}"
rm -rf docs/_build

# Build HTML documentation
echo -e "${YELLOW}Building HTML documentation...${NC}"
sphinx-build -b html docs docs/_build/html

# Check if build was successful
if [ $? -eq 0 ]; then
    echo -e "${GREEN}Documentation built successfully!${NC}"
    echo -e "View at: file://$(pwd)/docs/_build/html/index.html"
    
    # Optional: Open in browser
    if command -v xdg-open &> /dev/null; then
        read -p "Open in browser? (y/n) " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            xdg-open "file://$(pwd)/docs/_build/html/index.html"
        fi
    fi
else
    echo -e "${RED}Documentation build failed!${NC}"
    exit 1
fi
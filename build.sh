#!/bin/bash

# Build script for PugDNS with version information

VERSION=${VERSION:-"dev"}
BUILD_TIME=$(date -u '+%Y-%m-%d_%H:%M:%S')
GIT_COMMIT=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")

LDFLAGS="-X main.Version=$VERSION -X main.BuildTime=$BUILD_TIME -X main.GitCommit=$GIT_COMMIT"

echo "Building PugDNS..."
echo "Version: $VERSION"
echo "Build Time: $BUILD_TIME"
echo "Git Commit: $GIT_COMMIT"

go build -ldflags "$LDFLAGS" -o pugdns .

if [ $? -eq 0 ]; then
    echo "Build successful! Binary: ./pugdns"
    echo ""
    echo "Example usage:"
    echo "  ./pugdns --help                    # Show all options"
    echo "  ./pugdns --version                 # Show version info"
    echo "  ./pugdns --generate-config config.yaml  # Generate example config"
    echo "  ./pugdns -domains domains.txt --maxbatch 4096  # Run with high performance settings"
else
    echo "Build failed!"
    exit 1
fi 

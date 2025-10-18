#!/bin/bash
#
# ChaCha20 Cross-Verification Test Instructions
# This script replicates the cross-verification test manually
#

echo "ChaCha20 Cross-Verification Test"
echo "================================="
echo ""

# Navigate to the project directory
cd /home/fosres/Personal/git/chacha20_claude

echo "Step 1: Compiling C CLI wrapper..."
gcc -Wall -Wextra -O2 -o chacha20_c_cli chacha20_c_cli.c
if [ $? -eq 0 ]; then
    echo "  ✓ C CLI wrapper compiled successfully"
else
    echo "  ✗ C compilation failed"
    exit 1
fi
echo ""

echo "Step 2: Compiling Go CLI wrapper..."
go build -o chacha20_go_cli chacha20_go_cli.go
if [ $? -eq 0 ]; then
    echo "  ✓ Go CLI wrapper compiled successfully"
else
    echo "  ✗ Go compilation failed"
    exit 1
fi
echo ""

echo "Step 3: Installing csprng dependency (if needed)..."
go get gitlab.com/xx_network/crypto/csprng
echo "  ✓ Dependencies installed"
echo ""

echo "Step 4: Running cross-verification program..."
echo "================================================"
echo ""
go run cross_verify.go

echo ""
echo "================================================"
echo "Cross-verification test complete!"
echo ""

echo "Step 5: Cleaning up executables..."
rm -f chacha20_c_cli chacha20_go_cli
echo "  ✓ Removed chacha20_c_cli and chacha20_go_cli"
echo ""

echo "To manually test a single test vector, recompile and use:"
echo ""
echo "  gcc -Wall -Wextra -O2 -o chacha20_c_cli chacha20_c_cli.c"
echo "  go build -o chacha20_go_cli chacha20_go_cli.go"
echo ""
echo "  KEY=\"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f\""
echo "  NONCE=\"000000000000004a00000000\""
echo "  COUNTER=\"1\""
echo "  PLAINTEXT=\"4c616469657320616e642047656e746c656d656e\""
echo ""
echo "  ./chacha20_c_cli \$KEY \$NONCE \$COUNTER \$PLAINTEXT"
echo "  ./chacha20_go_cli \$KEY \$NONCE \$COUNTER \$PLAINTEXT"
echo ""
echo "Both should output identical hex strings."

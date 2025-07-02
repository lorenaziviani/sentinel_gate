
BASE_URL="http://localhost:8080"
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}=== Rate Limiting Test Suite ===${NC}"
echo

# Test 1: Health check and Redis connectivity
echo -e "${YELLOW}1. Testing health checks and Redis connectivity${NC}"
echo "GET $BASE_URL/ready"
curl -s -w "\nStatus: %{http_code}\n" "$BASE_URL/ready" | jq '.'
echo

# Test 2: Basic rate limiting test (no auth)
echo -e "${YELLOW}2. Testing basic rate limiting (IP-based)${NC}"
echo "Making 5 requests to /test/rate-limit..."
for i in {1..5}; do
    echo "Request $i:"
    curl -s -w "Status: %{http_code}, Headers: [Limit: %{header_x-ratelimit-limit}, Remaining: %{header_x-ratelimit-remaining}]\n" \
         "$BASE_URL/test/rate-limit" | jq '.message' 2>/dev/null || echo "Rate limit exceeded"
    sleep 0.2
done
echo

# Test 3: Get rate limit stats
echo -e "${YELLOW}3. Getting rate limit statistics${NC}"
echo "GET $BASE_URL/test/rate-limit-stats?type=ip"
curl -s -w "\nStatus: %{http_code}\n" "$BASE_URL/test/rate-limit-stats?type=ip" | jq '.'
echo

# Test 4: Test with authentication
echo -e "${YELLOW}4. Testing rate limiting with authentication${NC}"
echo "Getting JWT token..."
LOGIN_RESPONSE=$(curl -s -X POST "$BASE_URL/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"username": "user", "password": "password123"}')

TOKEN=$(echo "$LOGIN_RESPONSE" | jq -r '.access_token')

if [ "$TOKEN" != "null" ] && [ "$TOKEN" != "" ]; then
    echo -e "${GREEN}✓ Login successful${NC}"
    
    echo "Making 3 authenticated requests to /test/rate-limit-auth..."
    for i in {1..3}; do
        echo "Authenticated Request $i:"
        curl -s -w "Status: %{http_code}, Headers: [Limit: %{header_x-ratelimit-limit}, Remaining: %{header_x-ratelimit-remaining}, Type: %{header_x-ratelimit-type}]\n" \
             -H "Authorization: Bearer $TOKEN" \
             "$BASE_URL/test/rate-limit-auth" | jq '.message' 2>/dev/null || echo "Rate limit exceeded"
        sleep 0.2
    done
else
    echo -e "${RED}✗ Login failed${NC}"
fi
echo

# Test 5: Reset rate limit
echo -e "${YELLOW}5. Testing rate limit reset${NC}"
echo "POST $BASE_URL/test/rate-limit-reset?type=ip"
curl -s -w "\nStatus: %{http_code}\n" -X POST "$BASE_URL/test/rate-limit-reset?type=ip" | jq '.'
echo

# Test 6: Test different endpoints with different limits
echo -e "${YELLOW}6. Testing different endpoint limits${NC}"
echo "Testing /auth/login endpoint (should have stricter limits)..."
for i in {1..3}; do
    echo "Login attempt $i:"
    curl -s -w "Status: %{http_code}, Headers: [Limit: %{header_x-ratelimit-limit}, Remaining: %{header_x-ratelimit-remaining}]\n" \
         -X POST "$BASE_URL/auth/login" \
         -H "Content-Type: application/json" \
         -d '{"username": "invalid", "password": "invalid"}' | head -1
done
echo

# Test 7: Rapid fire test to trigger rate limiting
echo -e "${YELLOW}7. Rapid fire test to trigger rate limiting${NC}"
echo "Making 15 rapid requests to trigger rate limit..."
for i in {1..15}; do
    STATUS=$(curl -s -w "%{http_code}" "$BASE_URL/test/rate-limit" -o /dev/null)
    if [ "$STATUS" = "429" ]; then
        echo -e "${RED}✗ Request $i: Rate limited (429)${NC}"
        break
    else
        echo -e "${GREEN}✓ Request $i: Success ($STATUS)${NC}"
    fi
done
echo

# Test 8: Check rate limit headers
echo -e "${YELLOW}8. Checking rate limit headers${NC}"
echo "Making request to check headers..."
curl -s -I "$BASE_URL/test/rate-limit" | grep -i "x-ratelimit"
echo

echo -e "${BLUE}=== Rate Limiting Tests Complete ===${NC}"
echo -e "${YELLOW}Tips:${NC}"
echo "- Check logs for detailed rate limiting information"
echo "- Redis must be running for rate limiting to work"
echo "- Rate limits are configured in configs/rate-limit-rules.yaml"
echo "- Environment-specific multipliers apply (dev=10x, staging=3x, prod=1x)" 
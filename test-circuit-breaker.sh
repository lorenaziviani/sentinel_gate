
set -e

GATEWAY_URL="http://localhost:8080"
ADMIN_USER="admin"
ADMIN_PASS="password123"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

print_step() {
    echo -e "${BLUE}[TESTE CIRCUIT BREAKER]${NC} $1"
}

print_success() {
    echo -e "${GREEN} SUCCESS:${NC} $1"
}

print_warning() {
    echo -e "${YELLOW} WARNING:${NC} $1"
}

print_error() {
    echo -e "${RED} ERROR:${NC} $1"
}

get_auth_token() {
    print_step "Logging in to get admin token..." >&2
    
    TOKEN_RESPONSE=$(curl -s -X POST "$GATEWAY_URL/auth/login" \
        -H "Content-Type: application/json" \
        -d "{\"username\":\"$ADMIN_USER\",\"password\":\"$ADMIN_PASS\"}")
    
    if echo "$TOKEN_RESPONSE" | grep -q '"access_token"'; then
        TOKEN=$(echo "$TOKEN_RESPONSE" | jq -r '.access_token')
        print_success "Token obtained successfully" >&2
        echo "$TOKEN"
    else
        print_error "Failed to obtain token: $TOKEN_RESPONSE" >&2
        exit 1
    fi
}

check_gateway() {
    print_step "Checking if the gateway is running..."
    
    if curl -s "$GATEWAY_URL/health" > /dev/null; then
        print_success "Gateway is running on $GATEWAY_URL"
    else
        print_error "Gateway is not accessible at $GATEWAY_URL"
        print_error "Ensure the gateway is running with 'go run cmd/gateway/main.go'"
        exit 1
    fi
}

test_circuit_breaker_endpoint() {
    print_step "Testando endpoint de circuit breaker..."
    
    RESPONSE=$(curl -s "$GATEWAY_URL/test/circuit-breaker")
    
    if echo "$RESPONSE" | grep -q "Circuit breaker test endpoint"; then
        print_success "Circuit breaker endpoint is working"
        echo "$RESPONSE" | jq '.'
    else
        print_error "Failed on circuit breaker endpoint: $RESPONSE"
    fi
}

check_initial_status() {
    local TOKEN=$1
    print_step "Checking initial status of circuit breakers..."
    
    RESPONSE=$(curl -s -H "Authorization: Bearer $TOKEN" \
        "$GATEWAY_URL/admin/circuit-breaker/status")
    
    echo "$RESPONSE" | jq '.'
    print_success "Initial status verified"
}

check_initial_metrics() {
    local TOKEN=$1
    print_step "Checking initial metrics of circuit breakers..."
    
    RESPONSE=$(curl -s -H "Authorization: Bearer $TOKEN" \
        "$GATEWAY_URL/admin/circuit-breaker/metrics")
    
    echo "$RESPONSE" | jq '.'
    print_success "Initial metrics verified"
}

test_simulated_failure() {
    local TOKEN=$1
    local SERVICE_NAME=$2
    
    print_step "Testing simulated failure for service: $SERVICE_NAME"
    
    print_step "Sending requests that fail to activate circuit breaker..."
    
    for i in {1..10}; do
        RESPONSE=$(curl -s -w "%{http_code}" -o /dev/null \
            -X POST "$GATEWAY_URL/test/force-failure/$SERVICE_NAME")
        
        if [ "$RESPONSE" = "500" ]; then
            echo -n "."
        else
            print_warning "Request $i returned code $RESPONSE instead of 500"
        fi
        
        sleep 0.5
    done
    
    echo
    print_success "10 failure requests sent"
    
    print_step "Checking state of circuit breakers after failures..."
    
    STATUS_RESPONSE=$(curl -s -H "Authorization: Bearer $TOKEN" \
        "$GATEWAY_URL/admin/circuit-breaker/status")
    
    echo "$STATUS_RESPONSE" | jq '.'
    
    if echo "$STATUS_RESPONSE" | grep -q '"state":"OPEN"'; then
        print_success "Circuit breaker was activated (state OPEN)"
    else
        print_warning "Circuit breaker was not activated yet"
    fi
}

test_requests_with_active_breaker() {
    local SERVICE_NAME=$1
    
    print_step "Testing requests for service with active circuit breaker..."
    
    RESPONSE=$(curl -s -w "%{http_code}" -H "Authorization: Bearer $TOKEN" \
        "$GATEWAY_URL/api/users/test")
    
    echo "Response code: $RESPONSE"
    
    if [ "$RESPONSE" = "503" ]; then
        print_success "Circuit breaker returned 503 Service Unavailable as expected"
    else
        print_warning "Request was not blocked by circuit breaker (code: $RESPONSE)"
    fi
}

test_fallback_headers() {
    local TOKEN=$1
    
    print_step "Checking fallback headers of circuit breaker..."
    
    HEADERS=$(curl -s -I -H "Authorization: Bearer $TOKEN" \
        "$GATEWAY_URL/api/users/test")
    
    echo "$HEADERS"
    
    if echo "$HEADERS" | grep -q "X-Circuit-Breaker"; then
        print_success "Circuit breaker headers found"
    else
        print_warning "Circuit breaker headers not found"
    fi
    
    if echo "$HEADERS" | grep -q "Retry-After"; then
        print_success "Header Retry-After found"
    else
        print_warning "Header Retry-After not found"
    fi
}

test_reset_circuit_breaker() {
    local TOKEN=$1
    local SERVICE_NAME=$2
    
    print_step "Testing reset of circuit breaker for service: $SERVICE_NAME"
    
    RESPONSE=$(curl -s -X POST -H "Authorization: Bearer $TOKEN" \
        "$GATEWAY_URL/admin/circuit-breaker/reset/$SERVICE_NAME")
    
    if echo "$RESPONSE" | grep -q "has been reset"; then
        print_success "Circuit breaker reset successfully"
        echo "$RESPONSE" | jq '.'
    else
        print_error "Failed to reset circuit breaker: $RESPONSE"
    fi
}

check_final_metrics() {
    local TOKEN=$1
    
    print_step "Checking final metrics of circuit breakers..."
    
    RESPONSE=$(curl -s -H "Authorization: Bearer $TOKEN" \
        "$GATEWAY_URL/admin/circuit-breaker/metrics")
    
    echo "$RESPONSE" | jq '.'
    
    if echo "$RESPONSE" | grep -q '"requests_total"'; then
        print_success "Requests metrics found"
    fi
    
    if echo "$RESPONSE" | grep -q '"failures_total"'; then
        print_success "Failures metrics found"
    fi
    
    if echo "$RESPONSE" | grep -q '"fallback_executed"'; then
        print_success "Fallback metrics found"
    fi
}

test_configuration() {
    print_step "Testing configuration endpoint of circuit breaker..."
    
    RESPONSE=$(curl -s "$GATEWAY_URL/test/circuit-breaker")
    
    if echo "$RESPONSE" | grep -q "config_settings"; then
        print_success "Configuration of circuit breaker accessible"
        echo "$RESPONSE" | jq '.config_settings'
    else
        print_warning "Configuration not found in response"
    fi
}

main() {
    echo -e "${BLUE}"
    echo "=================================================="
    echo "           TEST CIRCUIT BREAKER"
    echo "              Sentinel Gate API Gateway"
    echo "=================================================="
    echo -e "${NC}"
    
    if ! command -v jq &> /dev/null; then
        print_error "jq is required to run this script"
        print_error "Install with: brew install jq (macOS) or apt-get install jq (Ubuntu)"
        exit 1
    fi
    
    check_gateway
    
    TOKEN=$(get_auth_token)
    
    # Basic tests
    echo -e "\n${YELLOW}=== BASIC TESTS ===${NC}"
    test_circuit_breaker_endpoint
    test_configuration
    check_initial_status "$TOKEN"
    check_initial_metrics "$TOKEN"
    
    # Failure tests
    echo -e "\n${YELLOW}=== FAILURE TESTS ===${NC}"
    test_simulated_failure "$TOKEN" "api-users"
    
    # Active circuit breaker tests
    echo -e "\n${YELLOW}=== ACTIVE CIRCUIT BREAKER TESTS ===${NC}"
    test_requests_with_active_breaker "api-users"
    test_fallback_headers "$TOKEN"
    
    # Recovery tests
    echo -e "\n${YELLOW}=== RECOVERY TESTS ===${NC}"
    test_reset_circuit_breaker "$TOKEN" "api-users"
    
    # Final metrics
    echo -e "\n${YELLOW}=== FINAL METRICS ===${NC}"
    check_final_metrics "$TOKEN"
    
    echo -e "\n${GREEN}"
    echo "=================================================="
    echo "           TESTS COMPLETED"
    echo "=================================================="
    echo -e "${NC}"
    
    print_success "All circuit breaker tests were executed"
    print_step "Check the gateway logs for more details"
}

# Executar função principal
main "$@" 
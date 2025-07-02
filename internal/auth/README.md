# Authentication Module

Sistema completo de autenticação JWT para o Sentinel Gate API Gateway com suporte a roles, refresh tokens e validação robusta.

## **Funcionalidades**

### **Autenticação JWT**

- **Login**: Autenticação com credenciais e geração de tokens
- **Refresh Token**: Renovação de tokens sem re-autenticação
- **Logout**: Invalidação segura de sessões
- **Claims Customizados**: Informações de usuário, role e metadados
- **Validação Completa**: Verificação de assinatura, expiração e claims

### **Controle de Acesso Baseado em Roles (RBAC)**

- **Middleware de Autorização**: Proteção automática de rotas
- **Roles Suportados**: admin, user, manager
- **Verificação Granular**: Validação por endpoint e método
- **Context Injection**: Informações de usuário disponíveis no contexto
- **Fallback Seguro**: Negação por padrão em caso de erro

### **Segurança e Validação**

- **Assinatura HMAC**: Verificação criptográfica de integridade
- **Validação Temporal**: Controle de expiração e not-before
- **Claims Obrigatórios**: Verificação de user_id, username, role
- **Token Masking**: Logs seguros sem exposição de tokens
- **Error Handling**: Respostas padronizadas para falhas

## **Arquitetura**

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│  Auth Handlers  │───▶│  JWT Middleware  │───▶│  RBAC Middleware │
└─────────────────┘    └──────────────────┘    └─────────────────┘
         │                       │                       │
         ▼                       ▼                       ▼
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│ Token Generation│    │ Token Validation │    │ Role Enforcement│
└─────────────────┘    └──────────────────┘    └─────────────────┘
```

### **JWT Token Structure**

```json
{
  "header": {
    "alg": "HS256",
    "typ": "JWT"
  },
  "payload": {
    "user_id": "uuid-v4",
    "username": "user",
    "role": "admin",
    "email": "user@example.com",
    "jti": "token-id",
    "exp": 1640995200,
    "iat": 1640908800,
    "nbf": 1640908800,
    "iss": "sentinel-gate",
    "sub": "user-id",
    "aud": ["sentinel-gate"]
  }
}
```

## **Configuração**

### **Environment Variables**

```bash
JWT_SECRET=your-secure-secret-key-minimum-32-characters
JWT_EXPIRATION=15m
JWT_REFRESH_EXPIRATION=7d
JWT_ISSUER=sentinel-gate
```

### **Configuração Go**

```go
type JWTConfig struct {
    Secret         string        `mapstructure:"secret"`
    ExpirationTime time.Duration `mapstructure:"expiration_time"`
    RefreshTime    time.Duration `mapstructure:"refresh_time"`
    Issuer         string        `mapstructure:"issuer"`
}
```

## **Endpoints de Autenticação**

### **POST /auth/login**

Autenticação com credenciais e geração de tokens.

**Request:**

```json
{
  "username": "user",
  "password": "password123"
}
```

**Response (200):**

```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIs...",
  "refresh_token": "eyJhbGciOiJIUzI1NiIs...",
  "token_type": "Bearer",
  "expires_in": 900,
  "user": {
    "id": "uuid-v4",
    "username": "user",
    "role": "admin",
    "email": "user@example.com"
  }
}
```

**Error (401):**

```json
{
  "error": "INVALID_CREDENTIALS",
  "message": "Invalid username or password",
  "request_id": "req_abc123"
}
```

### **POST /auth/refresh**

Renovação de access token usando refresh token.

**Request:**

```json
{
  "refresh_token": "eyJhbGciOiJIUzI1NiIs..."
}
```

**Response (200):**

```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIs...",
  "refresh_token": "eyJhbGciOiJIUzI1NiIs...",
  "token_type": "Bearer",
  "expires_in": 900,
  "user": {
    "id": "uuid-v4",
    "username": "user",
    "role": "admin"
  }
}
```

### **POST /auth/logout**

Logout do usuário (requer autenticação).

**Headers:**

```
Authorization: Bearer eyJhbGciOiJIUzI1NiIs...
```

**Response (200):**

```json
{
  "message": "Logout successful",
  "user_id": "uuid-v4",
  "username": "user",
  "request_id": "req_abc123"
}
```

## **Middleware Usage**

### **Proteção JWT Básica**

```go
// Proteger rota com autenticação JWT
router.GET("/protected",
    middleware.JWTAuth(jwtConfig, logger),
    handler)
```

### **Proteção com Role**

```go
// Apenas admins
router.GET("/admin",
    middleware.JWTAuth(jwtConfig, logger),
    middleware.RequireRole("admin"),
    adminHandler)

// Múltiplos roles
router.GET("/users",
    middleware.JWTAuth(jwtConfig, logger),
    middleware.RequireRole("user", "admin", "manager"),
    userHandler)
```

### **Acesso ao Context de Autenticação**

```go
func protectedHandler(c *gin.Context) {
    // Método 1: AuthContext completo
    authCtx, exists := c.Get("auth")
    if exists {
        auth := authCtx.(middleware.AuthContext)
        userID := auth.UserID
        username := auth.Username
        role := auth.Role
        email := auth.Email
        tokenID := auth.TokenID
    }

    // Método 2: Campos individuais
    userID, _ := c.Get("user_id")
    username, _ := c.Get("username")
    role, _ := c.Get("role")
    email, _ := c.Get("email")
}
```

## **Usuários de Teste**

### **Credenciais Padrão**

| Username  | Password      | Role      | Email                 |
| --------- | ------------- | --------- | --------------------- |
| `admin`   | `password123` | `admin`   | `admin@example.com`   |
| `user`    | `password123` | `user`    | `user@example.com`    |
| `manager` | `password123` | `manager` | `manager@example.com` |

### **Endpoints de Teste**

- **GET /test/public**: Acesso público (sem autenticação)
- **GET /test/protected**: Requer autenticação válida
- **GET /test/user**: Requer role `user` ou `admin`
- **GET /test/admin**: Requer role `admin`
- **POST /test/validate-token**: Validação e inspeção de token

## **Logs e Monitoramento**

### **Login Successful**

```json
{
  "level": "info",
  "message": "Login successful",
  "request_id": "req_abc123",
  "user_id": "uuid-v4",
  "username": "user",
  "role": "admin",
  "client_ip": "192.168.1.100"
}
```

### **JWT Authentication Successful**

```json
{
  "level": "debug",
  "message": "JWT authentication successful",
  "request_id": "req_abc123",
  "user_id": "uuid-v4",
  "username": "user",
  "role": "admin",
  "client_ip": "192.168.1.100"
}
```

### **Authentication Failed**

```json
{
  "level": "warn",
  "message": "JWT parsing error",
  "request_id": "req_abc123",
  "client_ip": "192.168.1.100",
  "token_preview": "eyJhbG...O68MvQ",
  "error": "signature is invalid"
}
```

### **Authorization Failed**

```json
{
  "level": "warn",
  "message": "Insufficient permissions",
  "request_id": "req_abc123",
  "username": "user",
  "required_roles": ["admin"],
  "current_role": "user"
}
```

## **Validações de Segurança**

### **Token Validation Checklist**

1. **Formato**: Verificação de estrutura JWT válida
2. **Assinatura**: Validação HMAC com secret
3. **Algoritmo**: Confirmação de HS256
4. **Expiração**: Verificação de `exp` claim
5. **Not Before**: Verificação de `nbf` claim
6. **Claims Obrigatórios**: Presença de `user_id`, `username`
7. **Issuer**: Validação do `iss` claim
8. **Audience**: Verificação do `aud` claim

### **Error Codes**

| Error Code                 | Descrição                    | HTTP Status |
| -------------------------- | ---------------------------- | ----------- |
| `UNAUTHORIZED`             | Token ausente ou inválido    | 401         |
| `INVALID_TOKEN`            | Token malformado             | 401         |
| `INVALID_CLAIMS`           | Claims inválidos             | 401         |
| `TOKEN_EXPIRED`            | Token expirado               | 401         |
| `TOKEN_NOT_VALID_YET`      | Token usado antes do tempo   | 401         |
| `INCOMPLETE_CLAIMS`        | Claims obrigatórios ausentes | 401         |
| `INSUFFICIENT_PERMISSIONS` | Role insuficiente            | 403         |

## **Testes Automatizados**

### **Suite de Testes (test-jwt.sh)**

1. **Public Access**: Endpoint público sem autenticação
2. **Protected Rejection**: Rejeição sem token
3. **Valid Login**: Login com credenciais válidas
4. **Invalid Credentials**: Rejeição de credenciais inválidas
5. **Token Access**: Acesso com token válido
6. **RBAC User**: Acesso com role de usuário
7. **RBAC Admin**: Proteção de endpoint admin
8. **Token Validation**: Validação e inspeção de tokens
9. **Token Refresh**: Renovação de tokens
10. **User Logout**: Processo de logout
11. **Invalid Token**: Rejeição de tokens inválidos
12. **Malformed Token**: Rejeição de tokens malformados

### **Executar Testes**

```bash
# Executar suite completa de testes JWT
./test-jwt.sh

# Verificar servidor antes dos testes
curl http://localhost:8080/health
```

## **Segurança**

### **Boas Práticas Implementadas**

- **Secret Forte**: Mínimo 32 caracteres para JWT_SECRET
- **Token Masking**: Logs seguros com tokens mascarados
- **Expiration Control**: Tokens com TTL configurável
- **Role Validation**: Verificação rigorosa de permissões
- **Request Tracking**: Request ID para auditoria
- **Error Sanitization**: Respostas padronizadas sem vazamento de informações

### **Considerações de Produção**

- **Token Blacklist**: Implementar para logout seguro
- **Password Hashing**: Usar bcrypt para senhas
- **Database Integration**: Substituir usuários hardcoded
- **Rate Limiting**: Aplicar limites em endpoints de auth
- **HTTPS Only**: Garantir transmissão segura de tokens
- **Token Rotation**: Estratégia de rotação de refresh tokens

## **Performance**

- **Latência**: < 1ms para validação de token (em memória)
- **Throughput**: Suporta milhares de validações/segundo
- **Memory**: Validação stateless sem armazenamento
- **CPU**: Operações criptográficas otimizadas

## **Compatibilidade**

- **Go 1.21+**: Testado e compatível
- **JWT Standard**: RFC 7519 compliant
- **Gin Framework**: Integração nativa
- **Logging**: Estruturado com zap
- **UUID**: RFC 4122 para identificadores únicos

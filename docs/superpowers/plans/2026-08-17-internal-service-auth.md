# 내부 서비스 인증 구현 계획

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Scheduler만 Secure Provisioner의 모든 `/internal/v1/*` API를 호출할 수 있도록 fail-closed Bearer token 인증을 구현한다.

**Architecture:** `cmd/provisioner`가 현재 token과 선택적인 이전 token을 환경 변수 또는 Secret 파일에서 읽어 형식과 설정 충돌을 검증한다. `internal/httpapi`는 원문 token을 SHA-256 digest로 바꿔 보관하는 middleware를 mux 바깥에 두고, 인증 성공 후에만 body 제한·route·Use Case로 요청을 전달한다. Scheduler 사용자 권한과 팀 소유권은 기존 시스템 경계대로 Scheduler가 담당한다.

현재 `instance-scheduler`에는 실제 Provisioner HTTP client 없이 `FakeRuntimeClient`만 있으므로
Scheduler repository에는 header를 삽입할 concrete call site가 없다. 이번 계획은 Provisioner의
인증 enforcement와 OpenAPI 연동 계약까지 완료하고, 실제 Scheduler HTTP client 구현 시 같은
token을 `Authorization` header로 공급하는 것을 명시적인 후속 연동점으로 남긴다.

**Tech Stack:** Go 1.24, `net/http`, `crypto/sha256`, `crypto/subtle`, `testing`, `httptest`, OpenAPI 3.1, YAML

## Global Constraints

- 외부 JSON 필드는 `snake_case`를 유지한다.
- 현재 token은 43~128자의 padding 없는 Base64URL 값이며 반드시 설정한다.
- 현재 token은 `PROVISIONER_SERVICE_TOKEN`과 `PROVISIONER_SERVICE_TOKEN_FILE` 중 정확히 하나에서 읽는다.
- 이전 token은 선택 사항이며 `PROVISIONER_PREVIOUS_SERVICE_TOKEN`과 `PROVISIONER_PREVIOUS_SERVICE_TOKEN_FILE` 중 최대 하나에서 읽는다.
- Secret 파일은 절대 경로만 허용하고 마지막 `LF` 또는 `CRLF` 한 개만 제거한다.
- 인증 누락·malformed·invalid 요청은 모두 동일한 `401 UNAUTHENTICATED` 응답을 반환한다.
- 인증은 Content-Type, JSON decode, request validation과 Use Case보다 먼저 수행한다.
- token 원문과 digest를 응답, Operation, Runtime Binding과 로그에 기록하지 않는다.
- 사용자 인증, 팀/소유권 판단, K3s/GHCR credential, HMAC와 mTLS는 범위에서 제외한다.
- 아직 존재하지 않는 Scheduler 실제 HTTP client 구현은 범위에서 제외하되 OpenAPI header 계약은 확정한다.

---

### Task 1: Service token 설정 로딩

**Files:**
- Create: `internal/httpapi/auth_config.go`
- Create: `cmd/provisioner/service_auth_config.go`
- Create: `cmd/provisioner/service_auth_config_test.go`
- Modify: `cmd/provisioner/main.go`
- Modify: `cmd/provisioner/main_test.go`

**Interfaces:**
- Consumes: `getenv func(string) string`, `os.ReadFile`, 네 service token 환경 변수
- Produces: `httpapi.ServiceAuthConfig{CurrentToken string, PreviousToken string}`가 포함된 `appConfig.ServiceAuth`
- Produces: `internal/httpapi/auth_config.go`의 transport-neutral `ServiceAuthConfig` 값 객체
- Produces: `loadServiceAuthConfig(getenv func(string) string) (httpapi.ServiceAuthConfig, error)`

- [ ] **Step 1: 설정 성공과 실패를 나타내는 테스트 작성**

`service_auth_config_test.go`에 다음 실제 동작을 각각 독립 test/subtest로 작성한다.

```go
const validCurrentServiceToken = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
const validPreviousServiceToken = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"

func TestLoadServiceAuthConfigAcceptsCurrentAndPreviousTokens(t *testing.T) {
	config, err := loadServiceAuthConfig(environment(map[string]string{
		"PROVISIONER_SERVICE_TOKEN":          validCurrentServiceToken,
		"PROVISIONER_PREVIOUS_SERVICE_TOKEN": validPreviousServiceToken,
	}))
	if err != nil {
		t.Fatal(err)
	}
	if config.CurrentToken != validCurrentServiceToken || config.PreviousToken != validPreviousServiceToken {
		t.Fatalf("config = %#v", config)
	}
}
```

실제 `t.TempDir()` 안의 절대 경로 파일을 사용해 마지막 `LF`와 `CRLF` 한 개가 제거되는지 검사한다. 누락, 직접 값과 파일 동시 설정, 상대 파일 경로, 읽기 실패, 42자, 129자, 공백, `+`, `/`, `=`, 두 줄바꿈, 현재·이전 token 동일 값을 각각 거부하는 literal test case를 추가한다.

- [ ] **Step 2: 설정 테스트가 RED인지 확인**

Run: `go test ./cmd/provisioner -run 'TestLoadServiceAuthConfig|TestLoadConfig' -count=1`

Expected: `loadServiceAuthConfig` 또는 `appConfig.ServiceAuth`가 없어 compile FAIL.

- [ ] **Step 3: 최소 설정 로더 구현**

`service_auth_config.go`에 다음 경계를 구현한다.

먼저 `internal/httpapi/auth_config.go`에 Task 2 middleware도 함께 사용하는 값 객체만 선언한다.

```go
type ServiceAuthConfig struct {
	CurrentToken  string
	PreviousToken string
}
```

```go
var serviceTokenPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{43,128}$`)

func loadServiceAuthConfig(getenv func(string) string) (httpapi.ServiceAuthConfig, error) {
	current, err := readServiceTokenSetting(getenv, "PROVISIONER_SERVICE_TOKEN", "PROVISIONER_SERVICE_TOKEN_FILE", true)
	if err != nil {
		return httpapi.ServiceAuthConfig{}, err
	}
	previous, err := readServiceTokenSetting(getenv, "PROVISIONER_PREVIOUS_SERVICE_TOKEN", "PROVISIONER_PREVIOUS_SERVICE_TOKEN_FILE", false)
	if err != nil {
		return httpapi.ServiceAuthConfig{}, err
	}
	if previous != "" && current == previous {
		return httpapi.ServiceAuthConfig{}, errors.New("current and previous service tokens must differ")
	}
	return httpapi.ServiceAuthConfig{CurrentToken: current, PreviousToken: previous}, nil
}
```

`readServiceTokenSetting`은 직접 값과 파일 설정의 배타성, 필수 여부, 절대 경로, 실제 file read, 마지막 line ending 한 개 제거와 정규식 검증을 한 곳에서 처리한다. 오류에는 token 값을 넣지 않는다.

`loadConfig`는 Registry 경로 확인 후 `loadServiceAuthConfig`를 호출하고 결과를 `appConfig.ServiceAuth`에 저장한다. 기존 config 테스트 입력에는 유효한 token을 명시한다.

- [ ] **Step 4: 설정 테스트와 전체 `cmd/provisioner` 테스트가 GREEN인지 확인**

Run: `go test ./cmd/provisioner -count=1`

Expected: PASS.

- [ ] **Step 5: 설정 구현 커밋**

```powershell
git add internal/httpapi/auth_config.go cmd/provisioner/main.go cmd/provisioner/main_test.go cmd/provisioner/service_auth_config.go cmd/provisioner/service_auth_config_test.go
git commit -m "Feat: 서비스 인증 Secret 설정 검증" -m "- 현재 token을 필수로 읽고 직접 값과 파일 설정 충돌을 거부" -m "- 이전 token 한 개와 안전한 교체 설정을 검증"
```

---

### Task 2: Bearer 인증 middleware와 애플리케이션 연결

**Files:**
- Create: `internal/httpapi/auth.go`
- Create: `internal/httpapi/auth_test.go`
- Modify: `internal/httpapi/http.go`
- Modify: `internal/httpapi/http_test.go`
- Modify: `internal/httpapi/runtime_test.go`
- Modify: `cmd/provisioner/main.go`
- Modify: `cmd/provisioner/main_test.go`

**Interfaces:**
- Consumes: `ServiceAuthConfig`, HTTP `Authorization` header
- Produces: `NewHandler(createWorkload, authConfig) http.Handler`
- Produces: `NewHandlerWithRuntime(createWorkload, runtime, authConfig) http.Handler`
- Produces: 인증 실패 시 `401`, `WWW-Authenticate: Bearer realm="secure-provisioner"`, `UNAUTHENTICATED` error envelope

- [ ] **Step 1: 인증 middleware 실패 테스트 작성**

`auth_test.go`에 다음 동작을 실제 handler를 통해 검증한다.

```go
func TestServiceAuthenticationRejectsMissingMalformedAndInvalidCredentials(t *testing.T) {
	testCases := []struct {
		name    string
		headers []string
	}{
		{name: "missing"},
		{name: "wrong scheme", headers: []string{"Basic abc"}},
		{name: "missing token", headers: []string{"Bearer"}},
		{name: "extra field", headers: []string{"Bearer wrong extra"}},
		{name: "wrong token", headers: []string{"Bearer CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"}},
		{name: "multiple headers", headers: []string{"Bearer AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "Bearer AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}},
	}
	// 모든 case에서 동일한 401 body와 WWW-Authenticate를 literal로 검증한다.
}
```

추가 테스트는 다음 mutation을 잡아야 한다.

- current token과 previous token 각각 성공
- auth scheme 대소문자 비구분과 token 대소문자 구분
- 현재 token이 비어 있는 handler는 어떤 credential도 통과시키지 않음
- 인증 실패 시 custom `io.ReadCloser`의 `Read`가 호출되지 않음
- 네 내부 route가 인증 없이 모두 401이며 runtime/create call count가 0

- [ ] **Step 2: 인증 테스트가 RED인지 확인**

Run: `go test ./internal/httpapi -run 'TestServiceAuthentication|TestAllInternalRoutesRequireServiceAuthentication' -count=1`

Expected: `ServiceAuthConfig`와 인증 middleware가 없어 compile FAIL.

- [ ] **Step 3: digest 기반 인증 middleware 구현**

`auth.go`에 Task 1의 `ServiceAuthConfig`를 받아 원문을 보관하지 않는 authenticator를 구현한다.

```go
type serviceAuthenticator struct {
	currentDigest  [sha256.Size]byte
	previousDigest [sha256.Size]byte
	hasCurrent     bool
	hasPrevious    bool
}
```

`Authorization`은 `Header.Values`가 정확히 한 개일 때만 `strings.Fields`로 두 field를 읽고,
scheme은 `strings.EqualFold`로 비교한다. 제공 token의 SHA-256 digest를 만든 뒤 현재와 이전
digest를 모두 `subtle.ConstantTimeCompare`한다. 인증 실패 시 `WWW-Authenticate`를 먼저
설정하고 기존 `writeAPIError`로 동일한 envelope를 쓴다.

- [ ] **Step 4: 모든 handler를 인증 경계 안에 배치**

`http.go`의 public constructor가 `ServiceAuthConfig`를 필수 인자로 받고 다음 순서로 handler를
반환하게 한다.

```go
return newServiceAuthenticator(authConfig).wrap(requestSizeLimit(mux))
```

test 전용 helper는 유효한 test token을 가진 실제 handler 바깥에서 모든 기존 요청에
`Authorization`을 주입한다. 기존 API 행동 테스트는 이 helper를 사용하고, 인증 전용 테스트는
raw public constructor를 사용한다.

- [ ] **Step 5: `newApplication`에 인증 설정 연결 및 통합 테스트 보완**

`newApplication`은 `config.ServiceAuth`를 `NewHandlerWithRuntime`에 전달한다. 기존
`TestNewApplicationQueuesCreateThroughRuntimeService`는 먼저 header 없는 요청이 401인지 확인한
후 같은 body와 현재 token으로 202를 확인한다.

- [ ] **Step 6: middleware와 HTTP 회귀 테스트가 GREEN인지 확인**

Run: `go test ./internal/httpapi ./cmd/provisioner -count=1`

Expected: PASS.

- [ ] **Step 7: 인증 middleware 구현 커밋**

```powershell
git add internal/httpapi/auth.go internal/httpapi/auth_test.go internal/httpapi/http.go internal/httpapi/http_test.go internal/httpapi/runtime_test.go cmd/provisioner/main.go cmd/provisioner/main_test.go
git commit -m "Feat: 내부 API Bearer 인증 적용" -m "- 모든 내부 route를 body 처리 전 인증" -m "- current와 previous token을 constant-time digest 비교"
```

---

### Task 3: OpenAPI와 운영 문서 계약

**Files:**
- Create: `internal/httpapi/openapi_auth_test.go`
- Modify: `docs/api/secure-provisioner.openapi.yaml`
- Modify: `docs/api/runtime-operations.md`
- Modify: `README.md`

**Interfaces:**
- Produces: OpenAPI `ServiceBearerAuth` HTTP bearer security scheme
- Produces: 모든 네 operation의 재사용 가능한 `Unauthenticated` 401 response
- Produces: Scheduler header, Secret file, local env와 rotation 운영 예제

- [ ] **Step 1: OpenAPI 인증 계약 실패 테스트 작성**

`openapi_auth_test.go`는 실제 YAML을 decode하고 다음 literal 계약을 검증한다.

```go
func TestOpenAPIRequiresServiceBearerAuthentication(t *testing.T) {
	// root security == [{"ServiceBearerAuth": {}}]
	// scheme type == "http", scheme == "bearer"
	// POST create, DELETE, GET operation, GET runtime-status가 모두 401 response를 가짐
}
```

OpenAPI 구조를 그대로 반영한 test struct를 사용하고 source text grep은 사용하지 않는다.

- [ ] **Step 2: OpenAPI 테스트가 RED인지 확인**

Run: `go test ./internal/httpapi -run TestOpenAPIRequiresServiceBearerAuthentication -count=1`

Expected: security scheme 또는 401 response가 없어 FAIL.

- [ ] **Step 3: OpenAPI 보안 계약 추가**

문서 root에 다음 보안을 적용한다.

```yaml
security:
  - ServiceBearerAuth: []
```

`components.securitySchemes.ServiceBearerAuth`는 `type: http`, `scheme: bearer`로 정의한다.
`components.responses.Unauthenticated`는 JSON `UNAUTHENTICATED` 예제와
`WWW-Authenticate` header를 포함하고, 네 operation의 `401`이 이 component를 참조한다.

- [ ] **Step 4: README와 runtime 연동 문서 갱신**

`README.md` 실행 설정에 네 환경 변수, Secret file 우선 원칙, HTTPS 운영 전제를 추가한다.
PowerShell 로컬 실행 예제에는 43자 test token을 넣는다. `runtime-operations.md`에는 모든 요청의
`Authorization: Bearer <service_token>`, 동일한 401 envelope와 token 교체 순서를 추가한다.
실제 secret 값은 문서나 로그에 출력하지 않는다.

- [ ] **Step 5: OpenAPI와 전체 HTTP 테스트가 GREEN인지 확인**

Run: `go test ./internal/httpapi -count=1`

Expected: PASS.

- [ ] **Step 6: API 문서 커밋**

```powershell
git add internal/httpapi/openapi_auth_test.go docs/api/secure-provisioner.openapi.yaml docs/api/runtime-operations.md README.md
git commit -m "Docs: 내부 API 인증 계약 명시" -m "- OpenAPI Bearer scheme과 공통 401 응답 추가" -m "- Secret 설정과 Scheduler 연동 절차 문서화"
```

---

### Task 4: 전체 검증과 보안 자체 리뷰

**Files:**
- Modify only if a failing verification has a focused TDD fix

**Interfaces:**
- Consumes: Tasks 1~3의 코드와 문서
- Produces: commit 가능한 clean diff와 검증 기록

- [ ] **Step 1: 형식과 정적 검증 실행**

Run:

```powershell
gofmt -w cmd/provisioner/*.go internal/httpapi/*.go
git diff --check
go vet ./...
go build ./cmd/provisioner
```

Expected: 모두 exit code 0.

- [ ] **Step 2: 전체 일반·race 테스트 실행**

Run:

```powershell
go test ./... -count=1
go test -race ./... -count=1
```

Expected: 모든 package PASS.

- [ ] **Step 3: 설계 요구사항과 mutation 자체 리뷰**

다음 잘못된 변경을 각 테스트가 잡는지 확인한다.

- 인증 wrapper 제거
- body 제한과 auth 순서 뒤집기
- previous token 비교 제거
- `ConstantTimeCompare` 대신 문자열 비교
- 여러 Authorization header 허용
- config 누락에서 기본 token 사용
- 파일 전체 whitespace trim
- OpenAPI operation 하나에서 401 누락

token/header 문자열이 `slog`, error formatting, Operation과 Binding에 전달되지 않는지 diff 전체를
검색한다. 발견한 결함은 실패 테스트를 먼저 추가해 수정한다.

- [ ] **Step 4: 최종 상태 확인**

Run:

```powershell
git status --short --branch
git diff origin/dev...HEAD --check
git log --oneline --decorate origin/dev..HEAD
```

Expected: 의도한 인증 설계·계획·설정·middleware·문서 커밋만 존재하고 unstaged 변경이 없다.

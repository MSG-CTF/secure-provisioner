# 내부 Provisioner API 서비스 인증 설계

> 상태: 구현 전 검토 초안. Scheduler와 Provisioner 담당자가 이 계약을 승인한 뒤 구현한다.

## 목적

`/internal/v1/*` API를 Scheduler만 호출할 수 있게 한다. 현재 HTTP handler는 인증 없이
생성, 조회, 삭제와 Operation 조회를 처리하므로 네트워크에 접근할 수 있는 주체가 임의로
인스턴스를 만들거나 지울 수 있다.

MVP에서는 사용자 로그인이나 팀 소유권을 Provisioner가 다시 판단하지 않는다. Scheduler가
사용자 인증, 팀별·사용자별 상한, 소유자 확인을 끝낸 뒤 내부 API를 호출하고,
Provisioner는 그 호출이 신뢰한 Scheduler에서 왔는지만 검증한다.

## 보호 범위

현재 서버가 제공하는 다음 API를 모두 같은 인증 경계 안에 둔다.

- `POST /internal/v1/instances`
- `DELETE /internal/v1/instances/{instance_id}`
- `GET /internal/v1/instances/{instance_id}/runtime-status`
- `GET /internal/v1/operations/{operation_id}`

인증 middleware는 mux 바깥을 감싸므로 잘못된 경로나 메서드도 먼저 인증한다. 따라서 유효한
서비스 자격 증명이 없는 요청은 route 존재 여부를 확인할 수 없다. 현재 별도 health endpoint는
없다. 추후 `healthz` 또는 `readyz`를 추가할 경우 참가자 네트워크와 분리된 관리 포트에 두고
별도 공개 여부를 결정한다.

## 검토한 방식

| 방식 | 장점 | 단점 | 결론 |
| --- | --- | --- | --- |
| 공유 Bearer token | 구현과 Scheduler 연동이 작고, 비밀값 교체가 쉬움 | TLS가 없으면 탈취 가능하고 호출자별 식별은 불가 | MVP 채택 |
| HMAC 서명 | body 변조와 제한적인 replay 방어 가능 | 시간 동기화, canonical JSON, nonce 저장과 재시도 규칙이 필요 | 후속 후보 |
| mTLS | 전송 암호화와 서비스 신원을 함께 검증 | 인증서 발급·회전·폐기 자동화와 proxy 설정이 먼저 필요 | 운영 고도화 후보 |

MVP는 무작위 256-bit 이상 공유 secret을 Bearer token으로 사용한다. Bearer 인증은 암호화를
제공하지 않으므로 운영에서는 HTTPS가 필수다. 애플리케이션을 loopback에 바인딩하고 앞단
reverse proxy에서 TLS를 종료하거나, Scheduler와 Provisioner 사이에서 직접 TLS를 사용한다.
평문 HTTP는 같은 호스트의 로컬 개발에만 허용한다.

## HTTP 계약

Scheduler는 모든 요청에 다음 header를 보낸다.

```http
Authorization: Bearer <service_token>
```

- 인증 scheme은 HTTP 규칙에 따라 대소문자를 구분하지 않는다.
- token 값은 대소문자를 구분한다.
- `Authorization` header가 없거나, 여러 개이거나, Bearer 형식이 아니거나, token이 일치하지
  않으면 모두 같은 실패로 처리한다.
- query string, cookie, JSON body에는 token을 허용하지 않는다.
- 유효한 token은 내부 API 전체 권한을 가진다. MVP에는 역할별 권한이나 `403 Forbidden`을
  두지 않는다.

인증 실패 응답은 원인을 구분하지 않는다.

```http
HTTP/1.1 401 Unauthorized
Content-Type: application/json
WWW-Authenticate: Bearer realm="secure-provisioner"
```

```json
{
  "error": {
    "code": "UNAUTHENTICATED",
    "message": "service authentication failed"
  }
}
```

인증은 Content-Type 검사, JSON decode, 요청 검증, Operation 생성보다 먼저 수행한다. 실패한
요청의 body는 읽지 않고 Use Case와 Kubernetes adapter도 호출하지 않는다. 인증이 성공한 뒤의
기존 상태 코드와 오류 envelope는 바꾸지 않는다.

## Secret 설정

운영에서는 Secret volume에 마운트한 파일을 우선 사용하고, 로컬 개발에서는 환경 변수도
허용한다.

| 용도 | 직접 값 | 파일 경로 |
| --- | --- | --- |
| 현재 token | `PROVISIONER_SERVICE_TOKEN` | `PROVISIONER_SERVICE_TOKEN_FILE` |
| 교체 중 이전 token | `PROVISIONER_PREVIOUS_SERVICE_TOKEN` | `PROVISIONER_PREVIOUS_SERVICE_TOKEN_FILE` |

설정 규칙은 다음과 같다.

1. 현재 token은 직접 값과 파일 중 정확히 하나가 반드시 있어야 한다.
2. 이전 token은 선택 사항이며, 설정한다면 직접 값과 파일 중 하나만 사용한다.
3. 파일 경로는 절대 경로여야 한다. Secret mount가 붙이는 마지막 `LF` 또는 `CRLF` 한 개만
   제거하고, 나머지 공백 문자는 거부한다.
4. token은 padding 없는 Base64URL 문자로 된 43~128자 값이어야 한다. 43자는 32 random
   bytes를 Base64URL로 표현한 길이다.
5. 현재 token과 이전 token이 같으면 시작을 거부한다.
6. 설정 누락, 중복, 파일 읽기 실패 또는 형식 오류가 있으면 서버를 열지 않고 fail-closed로
   종료한다. 인증 없는 fallback은 두지 않는다.

애플리케이션은 시작할 때 token을 읽어 SHA-256 digest로 변환하고 비교용 digest만
authenticator에 보관한다. 요청 token도 digest로 만든 뒤 `crypto/subtle`을 이용해 현재 값과
이전 값을 모두 constant-time 비교한다. 응답, 로그, Operation, Runtime Binding에는 원문이나
digest를 기록하지 않는다.

## Token 교체

중단 없는 자격 증명 교체를 위해 Provisioner만 이전 token 하나를 함께 받을 수 있다.

1. 새 token B를 현재 값, 기존 token A를 이전 값으로 Provisioner에 배포한다.
2. Scheduler를 token B로 교체한다.
3. 정상 호출을 확인한 뒤 Provisioner의 이전 token A를 제거한다.

이전 token에 자동 만료 시간을 두지는 않는다. 교체 작업 체크리스트에서 제거 확인을 필수로
하고, 장기간 두 token을 유지하지 않는다. token 유출 시에는 이 절차를 즉시 수행하며 로그에
token 자체를 넣어 유출 여부를 확인하지 않는다.

## 관측과 운영 경계

- 인증 실패 횟수는 HTTP 상태와 route template 기준 metric으로 집계할 수 있지만 header 값은
  label이나 로그에 넣지 않는다.
- 실패 로그에는 method, route, source가 신뢰 가능한 proxy에서 전달된 경우의 client 정보만
  남긴다. `Authorization`과 request body는 남기지 않는다.
- proxy가 외부의 `Authorization`을 그대로 통과시키는 경우에도 Provisioner가 직접 token을
  검증한다. 네트워크 ACL만으로 인증을 대체하지 않는다.
- Scheduler 외 새 내부 호출자가 필요해지면 같은 token을 공유해 확장하지 않고, 호출자별
  identity를 제공하는 mTLS 또는 서명 key 구조를 별도 설계한다.

## 코드 경계

승인 후 구현은 다음 경계를 따른다.

- `cmd/provisioner`: secret 설정을 읽고 잘못된 설정에서 시작을 중단한다.
- `internal/httpapi`: 모든 route 앞에서 동작하는 인증 middleware와 동일한 401 envelope를
  제공한다.
- OpenAPI와 연동 문서: HTTP Bearer security scheme, 전 API의 401 응답, Scheduler header
  예제를 추가한다.
- Scheduler: Provisioner client의 생성·삭제·상태·Operation 조회 요청에 같은 header를
  자동으로 넣는다. token은 요청 DTO나 DB에 저장하지 않는다.

HTTP handler를 인증 없이 만드는 production constructor는 남기지 않는다. 단위 테스트는
명시적인 테스트 token으로 handler를 만들고, 정상 경로 요청에 header를 추가한다.

## 검증 기준

- 현재 token과 교체 중 이전 token은 네 API 모두 통과한다.
- 누락, 잘못된 scheme, 여러 Authorization header, 틀린 token은 모두 동일한 401 body와
  `WWW-Authenticate`를 반환한다.
- 인증 실패 시 body를 읽지 않고 Use Case, Operation Store와 Kubernetes client를 호출하지
  않는다.
- 설정 누락, 직접 값·파일 중복, 짧거나 허용되지 않은 token, 같은 현재·이전 token에서
  `loadConfig`가 실패한다.
- token 또는 Authorization header가 오류 문자열과 캡처한 로그에 나타나지 않는다.
- 기존 API 성공·오류·멱등성 테스트는 인증 header를 추가한 상태로 모두 통과한다.
- OpenAPI validator가 security scheme과 401 응답을 포함한 문서를 통과한다.

## 범위 제외

- 참가자 사용자 인증과 세션
- `user_id`, `team_id`, 활성 인스턴스 상한과 소유자 판단
- Provisioner에서 K3s API, GHCR에 접근할 때 쓰는 별도 자격 증명
- request replay 방지를 위한 nonce 저장
- 인증서 자동 발급과 mTLS

## 사용자 검토가 필요한 결정

- MVP 호출자를 Scheduler 하나로 제한하는 것이 맞는지
- 운영 배포에서 TLS를 reverse proxy가 종료할지, 애플리케이션이 직접 처리할지
- 위의 이전 token 한 개를 이용한 교체 절차를 MVP에 포함할지

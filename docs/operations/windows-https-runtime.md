# Windows 11 HTTPS Runtime

Windows EXE의 선택 경로는 Backend → Runtime → Broker → VM HTTPS 실행기다.
Backend는 EXE를 비공개 저장소에 보관하고 Runtime의
`POST /v1/checker-submissions`에 메타데이터와 `selection_mode=broker_pool`을
보낸다. Runtime은 Backend의 `/internal/v1/checker-submissions/{id}/payload`에서
원본 EXE를 가져온다. Backend가 Broker 또는 VM의 실행기 API를 직접 호출하지 않는다.

## 활성화

- PostgreSQL Runtime 저장소와 마이그레이션을 먼저 준비한다.
- `PROVISIONER_WINDOWS_CONFIG`를 절대 경로의 JSON 설정 파일로 지정한다.
  [HTTPS 설정 예시](../../deploy/windows/config.https.example.json)를 참고한다.
- Broker Runtime 토큰은 `broker_token_file`에, VM 실행기 토큰과 VM의 자체 서명
  TLS 인증서는 `https_executor.targets[resource_target_id]`의 비공개 파일에 둔다.
  Broker 토큰을 VM에 설치하거나 실행기 토큰과 공유하지 않는다.
- 내부·외부 Backend에는 서로 다른 체커 서비스 토큰을 설정하고,
  `checker.backends`에는 Runtime에서 접근 가능한 HTTPS origin을 넣는다.
  Backend 쪽 `EXE_CHECKERS_JSON`의 서비스 토큰과 버전 해시는 Runtime 설정과
  일치해야 한다. 이 토큰은 VM 실행기 토큰과 별개다.
- 각 VM에는 [Windows 실행기 PR #88](https://github.com/MSG-CTF/secure-provisioner/pull/88)의
  실행기를 설치하고, 443 인바운드를 Runtime 송신 주소에만 허용한다.
  VM별 실행기 토큰과 인증서는 현재 정적 대상 설정에 등록해야 한다.

## 실행 순서

1. Runtime은 Broker의 `GET /v1/runtime/windows-vms`에서 READY 목록을 조회하고
   등록된 HTTPS 대상 중 하나를 고른다. 목록은 예약이 아니다.
2. Runtime은 선택한 VM의 최신 접속정보를 조회하고 같은 `execution_id`로
   `started` 이벤트를 보낸다. Broker가 `200/RUNNING`을 확인하기 전에는 EXE를
   보내지 않는다. `409`이면 그 VM을 사용하지 않는다.
3. Runtime은 Broker가 알려준 IP에 HTTPS로 접속한다. 등록한 인증서를 정확히
   검증하고 전용 토큰으로 EXE를 PUT한다. 실행기에서 결과를 조회하여 종료 코드와
   stdout/stderr를 저장한다.
4. Runtime은 Broker에 같은 ID의 `finished`를 영속 재시도한다. Broker가
   `200/RESET_REQUIRED`를 확인한 뒤 Backend에 `RESULT`를 통보한다.
   완료 통보가 유실돼도 저장된 ID와 본문으로 재시도한다.

## 현재 제한

- Broker READY는 HTTPS 실행기의 설치·도달 가능성을 증명하지 않는다.
- 새로운 VM은 현재 `https_executor.targets`에 인증정보를 등록해야 한다.
  동적 비밀 조회는 아직 구현되지 않았다.
- `finished` 이후 VM은 `RESET_REQUIRED`다. 자동 이미지 복구와 Backend의
  `CLEANUP(true)` 통보는 이 변경에 포함되지 않는다. 실제 채점 접수는
  이미지 복구·비밀값 전달·E2E 검증 후 활성화한다.
- Backend의 최초 체커 POST 응답이 불명확하고 이후 GET이 404이면 현재
  Backend는 자동 재접수를 하지 않고 작업을 보류한다. 운영자가 Runtime DB와
  Broker 이벤트 이력을 확인해야 한다.

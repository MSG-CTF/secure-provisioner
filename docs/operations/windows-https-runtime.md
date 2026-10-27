# Windows 11 HTTPS Runtime

Windows EXE의 선택 경로는 Backend → Runtime → Broker → VM HTTPS 실행기다.
Backend는 EXE를 비공개 저장소에 보관하고 Runtime의
`POST /v1/checker-submissions`에 메타데이터와 `selection_mode=broker_pool`을
보낸다. Runtime은 Backend의 `/internal/v1/checker-submissions/{id}/payload`에서
원본 EXE를 가져온다. Backend가 Broker 또는 VM의 실행기 API를 직접 호출하지 않는다.
새 `broker_pool` 요청에는 Backend active release가 필요 없으며 `release_id`를 생략한다.
이전 요청의 유효한 release UUID는 재전송 호환을 위해 허용하지만 VM 선택에는 쓰지 않는다.
고정 VM 방식에서는 release UUID를 계속 요구한다.
release 없는 Backend 코드를 적용하기 전에 이 Runtime 버전을 먼저 배포한다.
이전 Runtime은 새 요청을 400으로 거절하며, Backend는 불명확한 전송을 자동 재실행하지 않는다.

## 활성화

- PostgreSQL Runtime 저장소와 마이그레이션을 먼저 준비한다.
- `PROVISIONER_WINDOWS_CONFIG`를 절대 경로의 JSON 설정 파일로 지정한다.
  현재 배포 계약에는 [Broker mTLS 설정 예시](../../deploy/windows/config.broker-mtls.example.json)를 쓴다.
  [정적 토큰 HTTPS 예시](../../deploy/windows/config.https.example.json)는 별도 실행기용으로 유지한다.
- Broker Runtime 토큰은 `broker_token_file`에 둔다. VM HTTPS 실행에는
  `https_executor.client_certificate_file`과 `client_key_file`의 mTLS 자격증명을 쓴다.
  VM 서버 인증서는 Broker의 `executor_certificate_pem`을 받아 정확히 고정한다.
  Broker 토큰을 VM에 전송하지 않는다.
  운영 Runtime의 `root:provisioner` 비밀 파일은 `0640`을 허용한다.
  그룹 쓰기 권한이나 전체 사용자 권한은 허용하지 않는다.
- 내부·외부 Backend에는 서로 다른 체커 서비스 토큰을 설정하고,
  `checker.backends`에는 Runtime에서 접근 가능한 HTTPS origin을 넣는다.
  Backend 쪽 `EXE_CHECKERS_JSON`의 서비스 토큰, `checker_commit_sha`와
  `config_version`은 Runtime 설정과 일치해야 한다. `broker_pool`은 선택된 VM의
  이미지·드라이버 해시를 Broker가 제공하지 않으므로 두 해시를 요청과 RESULT에
  넣지 않는다. 고정 VM 경로의 승인 해시 검사는 유지한다. 이 토큰은 VM 실행기
  토큰과 별개다.
- 각 VM의 실행기는 Runtime 클라이언트 인증서를 검증하고 443 인바운드를 Runtime
  송신 주소에만 허용해야 한다. Broker가 READY로 반환한 VM은 동적으로 선택한다.

## 실행 순서

1. Runtime은 Broker의 `GET /v1/runtime/windows-vms`에서 READY 목록을 조회하고
   VM 하나를 고른다. 목록은 예약이 아니다.
2. Runtime은 선택한 VM의 최신 접속정보를 조회하고 같은 `execution_id`로
   `started` 이벤트를 보낸다. Broker가 `200/RUNNING`을 확인하기 전에는 EXE를
   보내지 않는다. `409`이면 그 VM을 사용하지 않는다.
3. Runtime은 Broker가 알려준 IP에 HTTPS로 접속한다. Broker가 준 VM 인증서를 정확히
   검증하고 Runtime 클라이언트 인증서로 EXE를 PUT한다. 실행기에서 결과를 조회하여 종료 코드와
   stdout/stderr를 저장한다.
4. Runtime은 Broker에 같은 ID의 `finished`를 영속 재시도한다. Broker가
   해당 ID의 `200/FINISHED`를 확인한 뒤 Backend에 `RESULT`를 통보한다.
   `vm_state`는 그 시점의 VM 상태이므로 복구 후 재전송에서는 `READY`일 수도 있다.
   완료 통보가 유실돼도 저장된 ID와 본문으로 재시도한다.

## 현재 제한

- Broker READY는 HTTPS 실행기의 설치·도달 가능성을 증명하지 않는다.
- 새 VM의 서버 인증서는 Broker 접속정보에 있어야 하고, 실행기는 Runtime 클라이언트
  인증서를 허용해야 한다. mTLS 모드에서는 VM별 정적 Runtime 설정을 추가하지 않는다.
- `finished` 이후 VM은 `RESET_REQUIRED`다. 자동 이미지 복구와 Backend의
  `CLEANUP(true)` 통보는 이 변경에 포함되지 않는다. 실제 채점 접수는
  이미지 복구·비밀값 전달·E2E 검증 후 활성화한다.
- Backend의 최초 체커 POST 응답이 불명확하고 이후 GET이 404이면 현재
  Backend는 자동 재접수를 하지 않고 작업을 보류한다. 운영자가 Runtime DB와
  Broker 이벤트 이력을 확인해야 한다.

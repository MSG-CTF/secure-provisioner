# 계약 예시

이 예시는 구현 전 제안이며 실제 Runtime 응답을 수집한 자료가 아니다.
`example` 이미지/digest, node, release, 시각과 작업 ID는 모두 가상 값이다.
토큰·Secret·kubeconfig는 포함하지 않는다.

- `query.json` → `response.json`: 같은 노드에 전체 이미지가 있는 target-a는 true,
  web/db가 서로 다른 노드에만 있는 target-b는 false다. unknown-target은 생략한다.
- `response-empty.json`: 요청한 target이 모두 미등록인 경우의 정상 200 응답이다.
- `response-unobserved.json`: 알려진 target의 최초 관측 전 상태다.
- `response-stale.json`: 예시를 00:01:00Z 이후 조회한 상황이다. 이전 실제 관측/만료
  시각을 보존하고 ready=false를 반환한다. API나 캐시 접근으로 시각을 갱신하지 않는다.
- `prepare.json` → `accepted.json` → `operation-partial.json`: 첫 노드는 전체 이미지
  준비가 끝났지만 두 번째 노드의 DB pull이 시도 소진으로 실패한 작업이다.
- `retry.json` → `retry-accepted.json`: 실패한 node UID만 새 child 작업으로 재시도한다.
- `create-tracing.json`: 기존 create 본문에 추가할 두 필드의 부분 예시다. 완전한 create
  요청이 아니며 현재 서버에 그대로 보내면 지원하지 않는 필드로 거절된다.
- `manifest.json`은 JSON 예시별 OpenAPI schema 이름의 매핑이다.

개발 검증:

```powershell
py -3 -m venv "$env:TEMP\msgctf-contract-venv"
& "$env:TEMP\msgctf-contract-venv\Scripts\python.exe" -m pip install PyYAML jsonschema openapi-spec-validator
& "$env:TEMP\msgctf-contract-venv\Scripts\python.exe" scripts/validate-image-preparation-contract.py
```

표준 CPython 환경을 사용한다. 별도 환경에서 개발 도구만 설치하며 운영 Runtime의
Python 의존성은 아니다. 검증은 schema·예시·교차 필드·오류 입력을 검사하며 실제
노드 pull, 같은 노드 조건의 구현, 정책 적용, 300ms 성능을 입증하지 않는다.

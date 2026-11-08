# MSG CTF Secure Provisioner

스케줄러가 선택한 실행 대상에 문제를 띄우고 격리·접속·삭제를 처리하는 Go 런타임입니다
K3s 컨테이너 실행과 전용 VM·Windows 연동을 구분하고, 작업 상태와 정리 결과를 API로 돌려줍니다

[플랫폼 전체 소개](https://github.com/MSG-CTF/msg-ctf.github.io)

## 맡은 일

- 단일·다중 컨테이너의 Namespace·Deployment·Service 생성과 준비 확인
- 네트워크·프로세스·자원 격리와 승인된 이미지별 실행 정책
- 백엔드 비밀값 조회와 컨테이너별 플래그·환경변수 주입
- HTTP·TCP Gateway, 접속 경로 회수와 실제 Kubernetes 자원 삭제
- 영속 작업·체크포인트·재시도와 재시작 후 생성·정리 복구
- 이미지 사전 준비·기동 CPU 복귀, KOTH 저장소 백업·복구와 Windows 실행 연결

## 함께 만든 사람들

| 기여자 | 기여 내용 | 관련 PR |
| --- | --- | --- |
| [goldsimchoi](https://github.com/goldsimchoi) | Runtime API·작업 워커·K3s 배포·격리, Gateway와 Windows 실행 경로 | [#20](https://github.com/MSG-CTF/secure-provisioner/pull/20) · [#34](https://github.com/MSG-CTF/secure-provisioner/pull/34) · [#92](https://github.com/MSG-CTF/secure-provisioner/pull/92) |
| [jongcoding](https://github.com/jongcoding) | 운영 연동·장애 QA, 기동·삭제 대기 개선과 KOTH 저장·복구 도구 | [#113](https://github.com/MSG-CTF/secure-provisioner/pull/113) · [#117](https://github.com/MSG-CTF/secure-provisioner/pull/117) · [#130](https://github.com/MSG-CTF/secure-provisioner/pull/130) |
| [gonas0919](https://github.com/gonas0919) | Windows 실행기 mTLS 설정 연동 | [#88](https://github.com/MSG-CTF/secure-provisioner/pull/88) |
| [dnehdx](https://github.com/dnehdx) | RE:QR 문제 이미지 실행 정책 수정 | [#135](https://github.com/MSG-CTF/secure-provisioner/pull/135) |

2026-11-09까지 병합된 PR과 커밋을 기준으로 정리했습니다

## 기술 구성

Go · Kubernetes/K3s · PostgreSQL · Docker · Nginx

## 개발·운영 문서

실행 코드와 운영 문서는 [dev 브랜치](https://github.com/MSG-CTF/secure-provisioner/tree/dev)에 있습니다

- [런타임 API](https://github.com/MSG-CTF/secure-provisioner/blob/dev/docs/api/runtime-operations.md)
- [백엔드 비밀값 주입](https://github.com/MSG-CTF/secure-provisioner/blob/dev/docs/operations/backend-secret-injection.md)
- [이미지 사전 준비](https://github.com/MSG-CTF/secure-provisioner/blob/dev/docs/operations/image-preparation.md)
- [K3s 삭제 대기 개선](https://github.com/MSG-CTF/secure-provisioner/blob/dev/docs/operations/sqlite-namespace-cache.md)

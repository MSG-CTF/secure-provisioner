# KOTH 이미지 준비

KOTH VM에는 레지스트리 인증값을 저장하지 않습니다
관리 서버의 이미지 전달 서비스가 승인한 GHCR 이미지를 OCI 파일로 받아 두고, 문제 VM은 5분 동안 유효한 이미지별 티켓으로 그 파일만 받습니다

1. 전용 VM 에이전트가 현재 적용 요청의 이미지 캐시를 확인합니다
2. 이미지가 없으면 백엔드에 현재 application_id, version_id, image_ref로 티켓을 요청합니다
3. 백엔드는 VM별 인증과 현재 적용 요청을 확인하고 해당 digest에만 유효한 티켓을 발급합니다
4. 관리 서버는 티켓의 서명·만료·이미지를 확인하고 OCI 파일을 전달합니다
5. VM은 전송 해시, OCI 경로와 각 blob의 digest를 검사한 뒤 containerd로 가져옵니다
6. 실제 이미지와 환경변수를 확인한 뒤에만 백엔드에 적용 완료를 알립니다

이미지 준비 실패는 실행 중인 Pod를 바꾸지 않고 관리자 화면에 이유를 남깁니다
현재 이미지가 캐시에 있으면 티켓 발급이나 재다운로드를 하지 않습니다

백엔드 설정

- KOTH_IMAGE_EXPORT_URL: 관리 서버의 HTTPS /internal/v1/koth_image_exports 주소
- KOTH_IMAGE_EXPORT_SIGNING_KEY: 관리 서버와 공유하는 이미지 티켓 전용 키

VM 에이전트 설정에는 image_export_url로 같은 HTTPS 주소만 등록합니다
VM에는 티켓 서명 키나 레지스트리 인증값을 넣지 않습니다

관리 서버는 deploy/koth-image-exporter.service로 실행합니다
별도 사용자 msg-koth-export가 127.0.0.1:9402에만 바인딩하며 기존 HTTPS 프록시에서 정확한 경로 하나만 연결합니다
/etc/msgctf-koth-image-exporter/config.json은 root 소유, 서비스 그룹 읽기만 허용하는 0640으로 둡니다

    {
      "signing_key": "관리 서버와 백엔드가 공유하는 전용 키",
      "registry_username": "운영 레지스트리 계정",
      "registry_password": "운영 레지스트리 인증값",
      "cache_dir": "/var/lib/msgctf-koth-image-exporter"
    }

캐시는 서비스 사용자만 읽는 0700 디렉터리에 둡니다
이미지 한 개는 2GiB까지, 캐시는 4GiB까지 보관하며 캐시의 오래된 OCI 파일만 정리합니다
GCS 참가자 파일과 문제 상태 볼륨은 이 정리 대상에 포함되지 않습니다

OCI 전달 서비스는 프로그램을 실행하지 않으며, 원래 manifest와 layer digest를 유지합니다
레지스트리 응답의 리다이렉트에는 인증 헤더를 전달하지 않습니다
요청 헤더·티켓·환경변수·레지스트리 응답 본문은 로그에 남기지 않습니다

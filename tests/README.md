# 공용 API 테스트

프로젝트 루트에서 실행합니다.

```powershell
python -m unittest discover -s tests
```

`test_app.py`는 이전 메모리 기반 API용 테스트로 현재 DB 기반 구현과 맞지 않는 항목이 있습니다.
`test_honeytoken_response.py`의 DB 통합 테스트에는 실행 중인 로컬 MySQL과 초기화된 웹앱 테이블이 필요합니다.
파일 이동과 무관한 기존 테스트의 전체 성공을 보장하는 명령은 아닙니다.

DB 없이 수신부·번호 규칙만 확인하려면 다음을 실행합니다.

```powershell
python -m unittest tests.test_incident_prefixes tests.test_killchain_response tests.test_honeytoken_response.HoneytokenResponseTest.test_invalid_payload_does_not_write tests.test_honeytoken_response.HoneytokenResponseTest.test_changed_contract_and_atomic_failure tests.test_honeytoken_response.HoneytokenResponseTest.test_ip_only_and_optional_metadata
```

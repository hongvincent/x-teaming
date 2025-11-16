# LLM 사이버보안 플랫폼 에이전트 아키텍처

## 개요
이 문서는 SecureAI Platform의 멀티 에이전트 아키텍처를 정의합니다. 각 에이전트는 특정 보안 도메인과 작업에 특화되어 있으며, 중앙 오케스트레이터를 통해 조정됩니다.

## 에이전트 계층 구조

```
┌─────────────────────────────────────────────────┐
│          보안 오케스트레이터 에이전트             │
│  (모든 에이전트 조정, 요청 라우팅)                │
└─────────────────┬───────────────────────────────┘
                  │
        ┌─────────┴──────────┐
        │                    │
┌───────▼────────┐    ┌─────▼──────────────┐
│ 도메인 에이전트  │    │  지원 에이전트      │
└───────┬────────┘    └─────┬──────────────┘
        │                   │
        ├─ 네트워크 보안 에이전트
        ├─ 소프트웨어 보안 에이전트
        ├─ 정보 보안 에이전트
        ├─ 하드웨어 보안 에이전트
        ├─ 블록체인 보안 에이전트
        ├─ 클라우드 보안 에이전트
        ├─ 사고 대응 에이전트
        └─ IoT 보안 에이전트
                             │
                             ├─ LLM 인터페이스 에이전트
                             ├─ 데이터 처리 에이전트
                             ├─ 로깅 & 모니터링 에이전트
                             └─ 보고 에이전트
```

## 핵심 에이전트

### 1. 보안 오케스트레이터 에이전트
**역할**: 모든 보안 작업의 중앙 조정자

**책임**:
- 보안 요청을 적절한 도메인 에이전트로 라우팅
- 여러 에이전트의 결과 집계
- 워크플로우 및 작업 의존성 관리
- 에러 복구 및 대체 전략 처리
- 전체 시스템 상태 모니터링

**주요 메서드**:
```python
- analyze_request(request: SecurityRequest) -> DomainRoute
- coordinate_multi_agent_task(task: ComplexTask) -> AggregatedResult
- prioritize_alerts(alerts: List[Alert]) -> PrioritizedAlerts
- orchestrate_incident_response(incident: Incident) -> ResponsePlan
```

---

## 도메인별 에이전트 (8개)

### 2. 네트워크 보안 에이전트 ✅
**전문 분야**: 네트워크 수준 보안 작업 (4개 모듈)

**하위 모듈**:
1. **Web Fuzzing Module** - SQL injection, XSS 탐지
2. **Traffic & Intrusion Detection Module** - 네트워크 트래픽 이상 탐지
3. **Cyber Threat Intelligence Module** - CTI 보고서 생성, IOC 추출
4. **Penetration Testing Module** - 자동화된 모의 침투 테스트

**위치**: `src/domains/network_security/`
**파일**: `network_security_agent.py`

**주요 기능**:
- SQL Injection 페이로드 생성
- 악성 URL 탐지
- 위협 행위자 프로파일링
- 취약점 익스플로잇 생성

---

### 3. 소프트웨어 & 시스템 보안 에이전트 ✅
**전문 분야**: 코드 및 시스템 수준 보안 (8개 모듈)

**하위 모듈**:
1. **Vulnerability Detection Module** - 정적 코드 분석
2. **Vulnerability Repair Module** - 자동 취약점 패치
3. **Bug Detection Module** - 버그 및 코드 스멜 탐지
4. **Bug Repair Module** - 자동 버그 수정
5. **Program Fuzzing Module** - 테스트 케이스 생성
6. **Reverse Engineering Module** - 바이너리 분석 및 디컴파일
7. **Malware Detection Module** - 악성코드 분류
8. **System Log Analysis Module** - 로그 이상 탐지

**위치**: `src/domains/software_security/`
**파일**: `software_security_agent.py`

**지원 언어**: Python, JavaScript, Java, C/C++, Go, Rust, Solidity, PHP, Ruby

**주요 기능**:
- CWE 매핑을 통한 취약점 탐지
- 자동 패치 생성 및 검증
- 로직 에러 식별
- 악성코드 패밀리 분류

---

### 4. 정보 & 콘텐츠 보안 에이전트 ✅
**전문 분야**: 정보 보안 및 콘텐츠 필터링 (5개 모듈)

**하위 모듈**:
1. **Phishing Detection Module** - 피싱 이메일/URL 탐지
2. **Harmful Content Detection Module** - 유해 콘텐츠 필터링
3. **Steganography Module** - 숨겨진 메시지 탐지
4. **Access Control Module** - 인증 및 접근 제어
5. **Digital Forensics Module** - 디지털 증거 추출

**위치**: `src/domains/information_security/`
**파일**: `information_security_agent.py`

**주요 기능**:
- 피싱 지표 추출
- 유해 콘텐츠 분류
- LSB 스테가노그래피 탐지
- 비밀번호 강도 평가

---

### 5. 하드웨어 보안 에이전트 ✅
**전문 분야**: 하드웨어 수준 보안 (2개 모듈)

**하위 모듈**:
1. **Hardware Vulnerability Detection Module** - HDL 취약점 탐지
2. **Hardware Vulnerability Repair Module** - 보안 어서션 생성

**위치**: `src/domains/hardware_security/`
**파일**: `hardware_security_agent.py`

**지원**: Verilog, VHDL

**주요 기능**:
- SoC 취약점 스캐닝
- 버퍼 오버플로우 탐지
- 타이밍 공격 분석

---

### 6. 블록체인 보안 에이전트 ✅
**전문 분야**: 블록체인 및 스마트 계약 보안 (2개 모듈)

**하위 모듈**:
1. **Smart Contract Security Module** - Solidity 스마트 계약 감사
2. **Transaction Anomaly Detection Module** - 의심스러운 거래 탐지

**위치**: `src/domains/blockchain_security/`
**파일**: `blockchain_security_agent.py`

**주요 기능**:
- Reentrancy 공격 탐지
- 정수 오버플로우/언더플로우
- 거래 패턴 분석
- 비정상적 가스 사용 탐지

---

### 7. 클라우드 보안 에이전트 ✅
**전문 분야**: 클라우드 인프라 보안 (4개 모듈)

**하위 모듈**:
1. **Misconfiguration Detection Module** - 클라우드 설정 오류 탐지
2. **Data Leakage Monitoring Module** - 데이터 유출 모니터링
3. **Container Security Module** - Docker/Kubernetes 보안
4. **Compliance Enforcement Module** - 규정 준수 검증

**위치**: `src/domains/cloud_security/`
**파일**: `cloud_security_agent.py`

**플랫폼**: AWS, Azure, GCP, Kubernetes

**주요 기능**:
- IAM 정책 분석
- PII 탐지 및 분류
- 컨테이너 이미지 스캐닝
- GDPR, SOC2, HIPAA 준수 검증

---

### 8. 사고 대응 에이전트 ✅
**전문 분야**: 보안 사고 대응 (4개 모듈)

**하위 모듈**:
1. **Alert Prioritization Module** - SIEM 경보 순위 지정
2. **Threat Intelligence Analysis Module** - 위협 정보 분석
3. **Threat Hunting Module** - 능동적 위협 헌팅
4. **Malware Reverse Engineering Module** - 악성코드 역공학

**위치**: `src/domains/incident_response/`
**파일**: `incident_response_agent.py`

**주요 기능**:
- 경보 심각도 평가
- IOC 추출 및 상관 분석
- 가설 기반 헌팅
- 악성코드 난독화 해제

---

### 9. IoT 보안 에이전트 ✅
**전문 분야**: IoT 장치 보안 (3개 모듈)

**하위 모듈**:
1. **Firmware Vulnerability Detection Module** - 펌웨어 취약점 탐지
2. **Behavioral Anomaly Detection Module** - 행동 이상 탐지
3. **Threat Report Summarization Module** - 위협 보고서 요약

**위치**: `src/domains/iot_security/`
**파일**: `iot_security_agent.py`

**주요 기능**:
- 펌웨어 바이너리 분석
- 하드코딩된 자격 증명 탐지
- IoT 트래픽 패턴 분석
- 봇넷 행동 탐지

---

## 지원 에이전트

### LLM 인터페이스 에이전트
**역할**: LLM API와의 통신 관리

**책임**:
- OpenAI API 호출 관리
- 프롬프트 엔지니어링
- 응답 파싱 및 검증
- 재시도 로직 및 에러 처리
- 응답 캐싱

**구현**: `src/utils/llm_client.py`

### 데이터 처리 에이전트
**역할**: 데이터 로딩 및 전처리

**책임**:
- 다양한 형식의 데이터 로드
- 데이터 정규화 및 변환
- 데이터 검증
- 샘플 데이터 생성

**구현**: `src/utils/data_loader.py`

### 로깅 & 모니터링 에이전트
**역할**: 시스템 로깅 및 모니터링

**책임**:
- 구조화된 로깅
- 성능 메트릭 수집
- 에러 추적
- 감사 로그 관리

**구현**: `src/utils/logger.py`

### 보고 에이전트
**역할**: 보안 보고서 생성

**책임**:
- 보안 분석 결과 집계
- 보고서 포맷팅
- 시각화 생성
- 보고서 배포

**구현**: 각 도메인 에이전트 내 통합

---

## 에이전트 간 통신

### 통신 프로토콜
```python
class AgentMessage:
    sender: str          # 발신 에이전트 ID
    recipient: str       # 수신 에이전트 ID
    task_type: str       # 작업 유형
    payload: Dict        # 작업 데이터
    priority: int        # 우선순위 (1-5)
    timestamp: datetime  # 타임스탬프
```

### 메시지 플로우
1. **요청** → 오케스트레이터가 적절한 도메인 에이전트로 라우팅
2. **처리** → 도메인 에이전트가 작업 수행
3. **응답** → 결과를 오케스트레이터로 반환
4. **집계** → 오케스트레이터가 결과 집계 및 반환

---

## 에이전트 상태 관리

### 상태 모니터링
```python
class AgentStatus:
    agent_id: str
    status: str          # active, busy, idle, error
    current_task: Optional[str]
    queue_length: int
    success_rate: float
    avg_response_time: float
```

### 상태 검증
각 에이전트는 `get_agent_status()` 메서드를 제공하여 현재 상태를 보고합니다.

---

## 확장성 및 유지보수

### 새 도메인 에이전트 추가
1. `src/domains/new_domain/` 디렉터리 생성
2. `NewDomainAgent` 클래스 구현
3. 필요한 모듈 구현
4. `__init__.py`에 export 추가
5. 오케스트레이터에 라우팅 규칙 추가

### 새 모듈 추가
1. 도메인 디렉터리에 새 모듈 파일 생성
2. 모듈 클래스 구현
3. 도메인 에이전트에 통합
4. 테스트 및 문서화

---

## 성능 최적화

### 캐싱 전략
- LLM 응답 캐싱 (동일한 요청에 대해)
- 분석 결과 캐싱
- 15분 TTL

### 병렬 처리
- 독립적인 작업은 병렬 실행
- 동시성 제한 설정
- 리소스 풀링

### 속도 제한
- API 호출 제한 준수
- 재시도 로직 (지수 백오프)
- 요청 큐잉

---

## 보안 고려사항

### 에이전트 보안
- 에이전트 간 통신 검증
- 입력 살균
- 출력 검증
- 권한 관리

### 데이터 보안
- PII 제거
- 민감 데이터 암호화
- 접근 제어
- 감사 로깅

---

## 문서 참조

### 추가 문서
- **[README_KR.md](README_KR.md)** - 프로젝트 개요
- **[PROJECT_STATUS_KR.md](PROJECT_STATUS_KR.md)** - 프로젝트 상태
- **[claude_KR.md](claude_KR.md)** - 프로젝트 계획

### 코드 예제
각 도메인 에이전트의 `__main__` 블록에서 사용 예제를 확인하세요.

### 데모
- `demos/demo_all_domains.py` - 전체 플랫폼 데모
- `demos/demo_network_security.py` - 네트워크 보안 데모
- `demos/demo_software_security.py` - 소프트웨어 보안 데모

---

**최종 업데이트**: 2025-11-16
**상태**: ✅ 전체 에이전트 구현 완료 (8/8 도메인)
**다음 단계**: 성능 최적화 및 추가 테스트

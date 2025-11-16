# OpenAI 모델 선택 가이드

## 🎯 개요

SecureAI Platform은 2025년 11월 기준 최신 OpenAI 모델을 지원합니다 (GPT-5.1, GPT-5, GPT-4.1, GPT-4o 시리즈). 이 가이드는 보안 작업에 적합한 모델 선택을 도와줍니다.

## 📊 사용 가능한 모델

### 플래그십 모델

#### GPT-5.1-chat-latest ⭐ **추천**
- **최적 용도**: 중요한 보안 결정, 복잡한 분석
- **특징**:
  - 적응형 추론 (자동으로 사고 시간 조절)
  - 최고 정확도 및 지능
  - 200K 토큰 컨텍스트 윈도우
  - 확장된 프롬프트 캐싱 (24시간)
- **사용 사례**:
  - 중요 취약점 분석
  - 복잡한 위협 인텔리전스
  - 전략적 보안 권장사항
  - 다단계 보안 추론

#### GPT-5
- **최적 용도**: 심층 보안 분석, 복잡한 추론 작업
- **특징**:
  - 강력한 추론 능력
  - 200K 토큰 컨텍스트 윈도우
  - 적응형 추론
- **사용 사례**:
  - 고급 코드 분석
  - 위협 행위자 프로파일링
  - 복잡한 공격 패턴 탐지

### 전문 모델

#### GPT-4.1
- **최적 용도**: 대규모 코드베이스 분석
- **특징**:
  - **100만 토큰** 컨텍스트 윈도우 (최대)
  - 16K 최대 출력 토큰
  - 긴 컨텍스트 작업에 탁월
- **사용 사례**:
  - 전체 저장소 취약점 스캔
  - 대형 스마트 계약 감사
  - 종합 시스템 로그 분석
  - 다중 파일 코드 분석

#### GPT-4o
- **최적 용도**: 멀티모달 보안 작업
- **특징**:
  - 멀티모달 기능 (텍스트 + 향후 이미지 지원)
  - 128K 토큰 컨텍스트
  - 속도와 품질의 균형
- **사용 사례**:
  - 일반 보안 분석
  - 네트워크 다이어그램 분석 (향후)
  - UI/UX 보안 검토 (향후)

### 성능 최적화 모델

#### GPT-5-mini 💰 **최고 가성비**
- **최적 용도**: 일반 보안 작업, 비용 최적화
- **특징**:
  - 탁월한 속도/품질 균형
  - 128K 컨텍스트 윈도우
  - 플래그십 대비 3-5배 빠름
  - 30-50% 비용 절감
- **사용 사례**:
  - 표준 취약점 스캔
  - 일상적인 위협 탐지
  - 로그 분석
  - 빠른 보안 평가

#### GPT-5-nano ⚡ **최고 속도**
- **최적 용도**: 간단하고 대량의 작업
- **특징**:
  - 가장 빠른 응답 시간
  - 최저 비용
  - 128K 컨텍스트 윈도우
- **사용 사례**:
  - 텍스트 분류
  - 빠른 요약
  - 간단한 패턴 매칭
  - IOC 추출

#### GPT-4o-mini
- **최적 용도**: 예산 중심의 일반 작업
- **특징**:
  - 비용 효율적
  - 128K 컨텍스트 윈도우
  - 일상 작업에 적합
- **사용 사례**:
  - 배치 처리
  - 간단한 분석 작업
  - 개발/테스트

## 🔄 자동 모델 선택

플랫폼은 작업 복잡도에 따라 최적의 모델을 자동으로 선택할 수 있습니다:

```python
from src.utils.llm_client import LLMClient

client = LLMClient()

# 복잡도에 따른 자동 선택
simple_result = client.complete(
    "이 로그에서 IOC 추출",
    task_complexity="simple"  # → gpt-5-nano 사용
)

complex_result = client.complete(
    "종합 보안 감사 수행",
    task_complexity="critical"  # → gpt-5.1-chat-latest 사용
)
```

### 복잡도 레벨

| 레벨 | 자동 선택 모델 | 최적 용도 |
|------|--------------|----------|
| **simple** | gpt-5-nano | 분류, 추출, 요약 |
| **medium** | gpt-5-mini | 표준 분석, 일상 스캔 |
| **complex** | gpt-5 | 심층 분석, 다단계 추론 |
| **critical** | gpt-5.1-chat-latest | 중요 결정, 종합 감사 |

## 🎛️ 수동 모델 선택

특정 요구사항에 따라 자동 선택 무시:

```python
# 특정 모델 사용
result = client.complete(
    prompt="이 스마트 계약 분석",
    model="gpt-4.1"  # 큰 컨텍스트를 위해 GPT-4.1 강제 사용
)

# 모델 프리셋 사용
result = client.complete(
    prompt="빠른 분류 작업",
    model=client.model_presets["fast"]  # gpt-5-nano 사용
)
```

### 모델 프리셋

| 프리셋 | 모델 | 사용 사례 |
|--------|------|----------|
| `flagship` | gpt-5.1-chat-latest | 최고 품질 |
| `reasoning` | gpt-5 | 심층 분석 |
| `longcontext` | gpt-4.1 | 대용량 파일/저장소 |
| `omni` | gpt-4o | 멀티모달 |
| `balanced` | gpt-5-mini | 최고 가성비 |
| `fast` | gpt-5-nano | 최고 속도 |
| `budget` | gpt-4o-mini | 최저 비용 |
| `legacy` | gpt-4 | 호환성 |

## 🔁 폴백 메커니즘

모델 실패 시 시스템이 자동으로 폴백 모델 시도:

**폴백 체인**: gpt-5.1 → gpt-5 → gpt-4.1 → gpt-4o → gpt-4

```python
# 폴백은 자동
result = client.complete(
    prompt="취약점 분석",
    use_fallback=True  # 기본값: 활성화
)
```

## 💡 모범 사례

### 비용 최적화

1. **적응형 선택 사용**: 시스템이 복잡도에 따라 선택하도록
2. **간단한 작업에는 -mini/-nano 선호**: 30-50% 비용 절감
3. **캐싱 활성화**: 응답이 15분간 캐시됨 (GPT-5.1은 24시간)
4. **유사한 요청 배치**: 캐시 히트로 API 비용 감소

```python
# 비용 최적화 접근법
client = LLMClient(use_cache=True)

# 간단한 작업 → 저렴한 모델
for log in logs:
    result = client.complete(log, task_complexity="simple")

# 복잡한 작업 → 강력한 모델
audit = client.complete(code, task_complexity="critical")
```

### 성능 최적화

1. **대량 작업에는 gpt-5-nano 사용**
2. **빠른 모델로 병렬 처리**
3. **요구사항에 따른 전략적 모델 선택**

```python
# 빠른 대량 처리
results = []
for item in large_dataset:
    result = client.complete(
        item,
        model="gpt-5-nano",  # 가장 빠름
        prefer_speed=True
    )
    results.append(result)
```

### 품질 극대화

1. **중요한 결정에는 GPT-5.1 사용**
2. **중요한 분석에 품질 모드 활성화**
3. **대용량 컨텍스트 요구사항에 GPT-4.1**

```python
# 최대 품질
result = client.complete(
    critical_code,
    prefer_quality=True,  # gpt-5.1-chat-latest 강제
    temperature=0.3       # 일관성을 위한 낮은 temperature
)
```

## 📈 성능 비교

| 모델 | 속도 | 품질 | 비용 | 컨텍스트 | 최적 사용 사례 |
|------|------|------|------|----------|---------------|
| gpt-5.1-chat-latest | 중간 | ⭐⭐⭐⭐⭐ | 높음 | 200K | 중요 분석 |
| gpt-5 | 중간 | ⭐⭐⭐⭐⭐ | 높음 | 200K | 복잡한 추론 |
| gpt-4.1 | 느림 | ⭐⭐⭐⭐ | 높음 | **1M** | 대규모 코드베이스 |
| gpt-4o | 빠름 | ⭐⭐⭐⭐ | 중간 | 128K | 일반 작업 |
| gpt-5-mini | 빠름 | ⭐⭐⭐⭐ | **낮음** | 128K | **최고 가성비** |
| gpt-5-nano | **가장 빠름** | ⭐⭐⭐ | **최저** | 128K | 대량 작업 |
| gpt-4o-mini | 빠름 | ⭐⭐⭐ | **최저** | 128K | 예산 작업 |

## 🔧 설정

`config/config.yaml` 편집으로 모델 동작 커스터마이즈:

```yaml
openai:
  # 기본 모델 설정
  model: "gpt-5.1-chat-latest"

  # 폴백 설정
  fallback_models:
    - "gpt-5"
    - "gpt-4.1"
    - "gpt-4o"

  # 적응형 선택 활성화
  adaptive_model_selection:
    enabled: true
    simple_tasks: "gpt-5-nano"
    medium_tasks: "gpt-5-mini"
    complex_tasks: "gpt-5"
    critical_tasks: "gpt-5.1-chat-latest"
    large_context: "gpt-4.1"
```

## 🎓 의사결정 트리

```
시작
  │
  ├─ 1M+ 토큰 컨텍스트 필요? → GPT-4.1
  │
  ├─ 중요한 보안 결정? → GPT-5.1-chat-latest
  │
  ├─ 복잡한 분석 필요? → GPT-5
  │
  ├─ 간단한 분류/추출? → GPT-5-nano
  │
  ├─ 비용이 주요 관심사? → GPT-5-mini
  │
  └─ 일반 작업? → GPT-5-mini (최고 가성비)
```

## 📝 예제

### 취약점 스캔

```python
# 대규모 저장소 - GPT-4.1 사용
result = client.complete(
    entire_codebase,
    model="gpt-4.1",  # 1M 컨텍스트
    task_complexity="complex"
)

# 단일 파일 - 적응형 사용
result = client.complete(
    single_file,
    task_complexity="medium"  # 자동으로 gpt-5-mini 선택
)
```

### 위협 인텔리전스

```python
# IOC 추출 - 빠른 모델
iocs = client.complete(
    threat_report,
    task_complexity="simple"  # gpt-5-nano
)

# 위협 행위자 프로파일링 - 품질 모델
profile = client.complete(
    campaign_data,
    task_complexity="critical"  # gpt-5.1-chat-latest
)
```

### 사고 대응

```python
# 경보 우선순위 지정 - 빠른 모델로 배치 처리
for alert in alerts:
    priority = client.complete(
        alert,
        model="gpt-5-nano",
        prefer_speed=True
    )

# 근본 원인 분석 - 품질 모델
root_cause = client.complete(
    incident_data,
    model="gpt-5.1-chat-latest",
    prefer_quality=True
)
```

## 🌟 요약

- **기본**: 적응형 선택 사용 (`task_complexity` 파라미터)
- **중요 작업**: GPT-5.1-chat-latest
- **대용량 파일**: GPT-4.1 (1M 컨텍스트)
- **최고 가성비**: GPT-5-mini
- **대량 작업**: GPT-5-nano
- **항상**: 캐싱 및 폴백 활성화

---

**최종 업데이트**: 2025년 11월
**플랫폼 버전**: 1.0.0

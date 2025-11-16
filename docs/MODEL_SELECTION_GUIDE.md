# OpenAI Model Selection Guide

## 🎯 Overview

SecureAI Platform supports the latest OpenAI models as of November 2025, including GPT-5.1, GPT-5, GPT-4.1, and GPT-4o series. This guide helps you choose the right model for your security tasks.

## 📊 Available Models

### Flagship Models

#### GPT-5.1-chat-latest ⭐ **RECOMMENDED**
- **Best for**: Critical security decisions, complex analysis
- **Features**:
  - Adaptive reasoning (automatically adjusts thinking time)
  - Highest accuracy and intelligence
  - 200K token context window
  - Extended prompt caching (24 hours)
- **Use cases**:
  - Critical vulnerability analysis
  - Complex threat intelligence
  - Strategic security recommendations
  - Multi-step security reasoning

#### GPT-5
- **Best for**: Deep security analysis, complex reasoning tasks
- **Features**:
  - Strong reasoning capabilities
  - 200K token context window
  - Adaptive reasoning
- **Use cases**:
  - Advanced code analysis
  - Threat actor profiling
  - Complex attack pattern detection

### Specialized Models

#### GPT-4.1
- **Best for**: Large codebase analysis
- **Features**:
  - **1 million token** context window (largest)
  - 16K max output tokens
  - Excellent for long-context tasks
- **Use cases**:
  - Full repository vulnerability scanning
  - Large smart contract auditing
  - Comprehensive system log analysis
  - Multi-file code analysis

#### GPT-4o
- **Best for**: Multimodal security tasks
- **Features**:
  - Multimodal capabilities (text + future image support)
  - 128K token context
  - Good balance of speed and quality
- **Use cases**:
  - General security analysis
  - Network diagram analysis (future)
  - UI/UX security review (future)

### Performance-Optimized Models

#### GPT-5-mini 💰 **BEST VALUE**
- **Best for**: General security tasks, cost optimization
- **Features**:
  - Excellent speed/quality balance
  - 128K context window
  - 3-5x faster than flagship
  - 30-50% cost savings
- **Use cases**:
  - Standard vulnerability scans
  - Routine threat detection
  - Log analysis
  - Quick security assessments

#### GPT-5-nano ⚡ **FASTEST**
- **Best for**: Simple, high-volume tasks
- **Features**:
  - Fastest response time
  - Lowest cost
  - 128K context window
- **Use cases**:
  - Text classification
  - Quick summarization
  - Simple pattern matching
  - IOC extraction

#### GPT-4o-mini
- **Best for**: Budget-conscious general tasks
- **Features**:
  - Cost-effective
  - 128K context window
  - Good for routine work
- **Use cases**:
  - Batch processing
  - Simple analysis tasks
  - Development/testing

## 🔄 Automatic Model Selection

The platform can automatically select the best model based on task complexity:

```python
from src.utils.llm_client import LLMClient

client = LLMClient()

# Automatic selection based on complexity
simple_result = client.complete(
    "Extract IOCs from this log",
    task_complexity="simple"  # → uses gpt-5-nano
)

complex_result = client.complete(
    "Perform comprehensive security audit",
    task_complexity="critical"  # → uses gpt-5.1-chat-latest
)
```

### Complexity Levels

| Level | Auto-Selected Model | Best For |
|-------|-------------------|----------|
| **simple** | gpt-5-nano | Classification, extraction, summarization |
| **medium** | gpt-5-mini | Standard analysis, routine scans |
| **complex** | gpt-5 | Deep analysis, multi-step reasoning |
| **critical** | gpt-5.1-chat-latest | Critical decisions, comprehensive audits |

## 🎛️ Manual Model Selection

Override automatic selection for specific needs:

```python
# Use specific model
result = client.complete(
    prompt="Analyze this smart contract",
    model="gpt-4.1"  # Force GPT-4.1 for large context
)

# Use model preset
result = client.complete(
    prompt="Quick classification task",
    model=client.model_presets["fast"]  # Uses gpt-5-nano
)
```

### Model Presets

| Preset | Model | Use Case |
|--------|-------|----------|
| `flagship` | gpt-5.1-chat-latest | Best quality |
| `reasoning` | gpt-5 | Deep analysis |
| `longcontext` | gpt-4.1 | Large files/repos |
| `omni` | gpt-4o | Multimodal |
| `balanced` | gpt-5-mini | Best value |
| `fast` | gpt-5-nano | Highest speed |
| `budget` | gpt-4o-mini | Lowest cost |
| `legacy` | gpt-4 | Compatibility |

## 🔁 Fallback Mechanism

If a model fails, the system automatically tries fallback models:

**Fallback Chain**: gpt-5.1 → gpt-5 → gpt-4.1 → gpt-4o → gpt-4

```python
# Fallback is automatic
result = client.complete(
    prompt="Analyze vulnerability",
    use_fallback=True  # Default: enabled
)
```

## 💡 Best Practices

### Cost Optimization

1. **Use adaptive selection**: Let the system choose based on complexity
2. **Prefer -mini/-nano for simple tasks**: 30-50% cost savings
3. **Enable caching**: Responses are cached for 15 minutes (or 24 hours with GPT-5.1)
4. **Batch similar requests**: Cache hits reduce API costs

```python
# Cost-optimized approach
client = LLMClient(use_cache=True)

# Simple tasks → cheap models
for log in logs:
    result = client.complete(log, task_complexity="simple")

# Complex tasks → powerful models
audit = client.complete(code, task_complexity="critical")
```

### Performance Optimization

1. **Use gpt-5-nano for bulk operations**
2. **Parallel processing** with fast models
3. **Strategic model selection** based on requirements

```python
# Fast bulk processing
results = []
for item in large_dataset:
    result = client.complete(
        item,
        model="gpt-5-nano",  # Fastest
        prefer_speed=True
    )
    results.append(result)
```

### Quality Maximization

1. **Use GPT-5.1 for critical decisions**
2. **Enable quality mode** for important analyses
3. **GPT-4.1 for large context** requirements

```python
# Maximum quality
result = client.complete(
    critical_code,
    prefer_quality=True,  # Forces gpt-5.1-chat-latest
    temperature=0.3       # Lower temperature for consistency
)
```

## 📈 Performance Comparison

| Model | Speed | Quality | Cost | Context | Best Use Case |
|-------|-------|---------|------|---------|---------------|
| gpt-5.1-chat-latest | Medium | ⭐⭐⭐⭐⭐ | High | 200K | Critical analysis |
| gpt-5 | Medium | ⭐⭐⭐⭐⭐ | High | 200K | Complex reasoning |
| gpt-4.1 | Slow | ⭐⭐⭐⭐ | High | **1M** | Large codebases |
| gpt-4o | Fast | ⭐⭐⭐⭐ | Medium | 128K | General tasks |
| gpt-5-mini | Fast | ⭐⭐⭐⭐ | **Low** | 128K | **Best value** |
| gpt-5-nano | **Fastest** | ⭐⭐⭐ | **Lowest** | 128K | Bulk operations |
| gpt-4o-mini | Fast | ⭐⭐⭐ | **Lowest** | 128K | Budget tasks |

## 🔧 Configuration

Edit `config/config.yaml` to customize model behavior:

```yaml
openai:
  # Set primary model
  model: "gpt-5.1-chat-latest"

  # Configure fallbacks
  fallback_models:
    - "gpt-5"
    - "gpt-4.1"
    - "gpt-4o"

  # Enable adaptive selection
  adaptive_model_selection:
    enabled: true
    simple_tasks: "gpt-5-nano"
    medium_tasks: "gpt-5-mini"
    complex_tasks: "gpt-5"
    critical_tasks: "gpt-5.1-chat-latest"
    large_context: "gpt-4.1"
```

## 🎓 Decision Tree

```
Start
  │
  ├─ Need 1M+ tokens context? → GPT-4.1
  │
  ├─ Critical security decision? → GPT-5.1-chat-latest
  │
  ├─ Complex analysis required? → GPT-5
  │
  ├─ Simple classification/extraction? → GPT-5-nano
  │
  ├─ Cost is primary concern? → GPT-5-mini
  │
  └─ General task? → GPT-5-mini (best value)
```

## 📝 Examples

### Vulnerability Scanning

```python
# Large repository - use GPT-4.1
result = client.complete(
    entire_codebase,
    model="gpt-4.1",  # 1M context
    task_complexity="complex"
)

# Single file - use adaptive
result = client.complete(
    single_file,
    task_complexity="medium"  # Auto-selects gpt-5-mini
)
```

### Threat Intelligence

```python
# IOC extraction - fast model
iocs = client.complete(
    threat_report,
    task_complexity="simple"  # gpt-5-nano
)

# Threat actor profiling - quality model
profile = client.complete(
    campaign_data,
    task_complexity="critical"  # gpt-5.1-chat-latest
)
```

### Incident Response

```python
# Alert prioritization - batch with fast model
for alert in alerts:
    priority = client.complete(
        alert,
        model="gpt-5-nano",
        prefer_speed=True
    )

# Root cause analysis - quality model
root_cause = client.complete(
    incident_data,
    model="gpt-5.1-chat-latest",
    prefer_quality=True
)
```

## 🌟 Summary

- **Default**: Use adaptive selection (`task_complexity` parameter)
- **Critical work**: GPT-5.1-chat-latest
- **Large files**: GPT-4.1 (1M context)
- **Best value**: GPT-5-mini
- **Bulk operations**: GPT-5-nano
- **Always**: Enable caching and fallback

---

**Last Updated**: November 2025
**Platform Version**: 1.0.0

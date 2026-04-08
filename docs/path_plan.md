## 11. 참고 문헌 및 관련 연구

본 아키텍처(Regex + 머신러닝/LLM 하이브리드 탐지 및 의미 기반 문맥 인지)는 최근 학계 및 산업계의 Data Loss Prevention(DLP) 연구 방향과 일치합니다. 다음은 본 설계와 유사한 접근 방식을 다루는 주요 연구 사례입니다:

1. **[An Evaluation Study of Hybrid Methods for Multilingual PII Detection](https://arxiv.org/abs/2510.07551)** (arXiv, 2025)
   - 기존 정규표현식(Regex)과 문맥 인지 대형 언어 모델(LLM)을 결합하여 다국어 환경에서 PII 탐지의 오탐을 줄이고 정확도를 높이는 하이브리드 프레임워크(RECAP) 연구.
2. **[A hybrid rule-based NLP and machine learning approach for PII detection and anonymization in financial documents](https://www.nature.com/articles/s41598-025-04971-9)** (Scientific Reports, 2025)
   - 금융 문서에서 룰 기반(Regex) NLP와 머신러닝(NER)을 결합하여 문맥과 포맷의 다양성을 처리하고 오탐을 완화하는 아키텍처 제안.
3. **[US20250005175A1 - Hybrid sensitive data scrubbing using patterns and large language models](https://patents.google.com/patent/US20250005175A1/en)** (US Patent, Crowdstrike, 2025)
   - 정규표현식 패턴 매칭과 대규모 언어 모델(LLM)의 출력을 결합하여 ��감한 데이터(PII 등)를 스크러빙하는 산업계(Crowdstrike)의 하이브리드 파이프라인 적용 사례.
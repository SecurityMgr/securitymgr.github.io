---
layout: post
title: 보안기사 이모저모
date: 2022-01-21 09:20:23 +0900
category: SecurityNews
---

# [ 보안기사 ]
---


#### 통가의 거대 화산 폭발 사태, 세계 통신망의 취약점 드러내다 [[Link]](https://www.boannews.com/media/view.asp?idx=104257&fbclid=IwAR2YlRVCYa-AUMWOVkGPKVoeHYOzRzFGcVDb0RTs0LHkwZm2-OLOC7f2bf8)
- 유례없는 규모의 화산 폭발로 해저 케이블 단절로 인해 인터넷과 인터넷 통신 두절로 국가전체 고립
- 전세계 데이터 트래픽의 95%가 해저 케이블을 통과하기 때문에 해저 화산사태를 비롯해 쓰나미, 허리케인, 태풍 등의 문제의 영향 존재

#### Campaigns abusing corporate trusted infrastructure hunt for corporate credentials on ICS networks [[Link]](https://ics-cert.kaspersky.com/publications/reports/2022/1/19/campaigns-abusing-corporate-trusted-infrastructure-hunt-for-corporate-credentials-on-ics-networks/?fbclid=IwAR1BZrW7gg95FwRuDMzU7wbm59VD5ZS-zff_j2aONdNO9aJtnt5yDhMen-s)
- ICS환경의 자격증명을 노리는 인프라 악용 공격 증가
 


#### Researchers Explore Hacking VirusTotal to Find Stolen Credentials [[Link]](https://thehackposts.com/researchers-explore-hacking-virustotal-to-find-stolen-credentials/)

Reference : The Perfect Cyber Crime [[Link]](https://www.safebreach.com/blog/2022/the-perfect-cyber-crime/)
- 의심스러운 기록 데이터 및 URL을 분석에 VirusTotal검색을 통한 Credentials 수집 방법을 확인
- 600유로(약 769달러, 한화 90만원 가량)으로 VirusTotal 라이선스 수집을 통해 다량의 정보 수집
- 범죄자들의 취약한 웹서비스, 사물인터넷장치, 웹쉘, 지식유출 들을 통한 Google해킹과 유사한 VirusTotal 해킹개념을 활용

#### 소프트웨어 취약점 패치, 속도보다 정확도가 중요하다 [[Link]](https://www.boannews.com/media/view.asp?idx=104254)
- Apache Log4j와 오픈소스 보안패치 등과 관련된 자료를 찾다가 발견한 좋은 사이트
- CVE와 보안패치 필요성에 대한 우선순위 기준 방안에 대한 연구자료

### 1. 개요
- 보안 업체 켄나시큐리티(Kenna Security)와 데이터 과학 전문 조직인 사이엔샤 인스티튜트(Cyentia Institute)가 공동으로 분석한 결과에 따르면 CVSS점수에 따라 취약점을 분류하고, 패치 우선순위를 결정하는 방법이 무작위로 패치하는 것보다 2~6배 효과
- 2배에서 6배의 차이를 만드는 가장 큰 요인은 패치 속도에 달렸으며, 빠른 패치일수록 효과가 급증
- 결국 CVE취약점 발견 히 Exploit Code의 존재여부를 조사하고 그런 코드가 공개된 취약점부터 패치하는 것이 높은 효과가 존재

### 2. 원본내용
Reference : Here’s How to Measure Your Organization’s Exploitability [[Link]](https://www.kennasecurity.com/blog/heres-how-to-measure-your-organizations-exploitability/)
- 보안업체 켄나시큐리티의 연구 시리즈인 “Prioritization to Prediction(예측 우선순위 지정)”을 통해 취약점으로 인한 악용가능성을 감소시키는 방법에 대해 연구

#### 2.1. 분석보고서 시리즈 [[Link]](https://www.kennasecurity.com/resources/prioritization-to-prediction-reports/)

#### 2.1.1. Prioritization to Prediction Volume 1 : Analyzing Vulnerability Remediation Strategies(취약점 개선전략 분석) [[Link]](https://website.kennasecurity.com/wp-content/uploads/2020/09/Kenna_Prioritization_to_Prediction_Vol1.pdf)
- 효과적인 치료는 조치를 취해야 하는 취약점과 그 중 가장 높은 우선 순위를 갖는 취약점을 신속하게 결정하는 데 달려 있지만 우선 순위 지정은 취약점 관리에서 가장 큰 과제 중 하나

#### 2.1.2. Prioritization to Prediction Volume 2 : Getting Real About Remediation(교정에 대한 현실화하기) [[Link]](https://website.kennasecurity.com/wp-content/uploads/2020/09/Kenna_Prioritization_to_Prediction_Vol2.pdf)
- Kenna Security의 연구는 Cyentia Institute와 협력하여 주요 기업의 취약성 관리 전략을 드물게 살펴보고 조직이 보안을 개선하면서 대부분의 취약성을 무시하는 방법을 제시


#### 2.1.3. Prioritization to Prediction Volume 3 : Winning the Remediation Race(개선 경쟁에서 승리) [[Link]](https://website.kennasecurity.com/wp-content/uploads/2020/09/Kenna_Prioritization_to_Prediction_Vol3.pdf)
- 보안 및 IT 팀은 점점 더 복잡해지는 사이버 보안 환경에 맞서 조직이 방어하기 위해 계속해서 취약점 게임에서 승기를 잡는 방법

#### 2.1.4. Prioritization to Prediction Volume 4 : Measuring What Matters in Remediation(교정에서 중요한 측정) [[Link]](https://website.kennasecurity.com/wp-content/uploads/2020/09/Kenna_Prioritization_to_Prediction_Vol4.pdf)
- 기업의 취약성 관리 관행에 대한 정성적 조사 데이터를 실제 개선 성과의 정량적 측정과 결합하여 고성능 취약성 관리 프로그램에 기여하는 비즈니스 요소

#### 2.1.5. Prioritization to Prediction Volume 5 : In Search of Assets at Risk [[Link]](https://website.kennasecurity.com/wp-content/uploads/2020/09/Kenna_Prioritization_to_Prediction_Vol_5.pdf)
- Cyentia Institute와 공동으로 제작한 Prioritization to Prediction 시리즈의 다섯 번째 볼륨은 기업이 공통 자산 플랫폼의 렌즈를 통해 취약점을 자주 보는 방식을 살펴봄으로써 취약점 위험 환경을 탐구

#### 2.1.6. Prioritization to Prediction Volume 6 : The Attacker-Defender Divide [[Link]](https://website.kennasecurity.com/wp-content/uploads/2020/12/Prioritization_to_Prediction_Volume_6___Attacker_Defender_Divide.pdf)
- 473개 취약점의 수명 주기를 야생에서의 악용의 증거와 함께 탐구하며 취약점이 발견된 후 실제 발생되는 일들을 분석
- 공격자와 방어자가 모멘텀을 갖는 시기와 장소, 책임있는 취약성 공개 및 Exploit 개발의 효율성 등에 대한 통찰력을 제공

##### 2.1.7. Prioritization to Prediction Volume 7 : Establishing Defender Advantage [[Link]](https://website.kennasecurity.com/wp-content/uploads/2021/05/Prioritization-to-Prediction-Volume-7-Establishing-Defender-Advantage.pdf)
- 익스플로잇 코드 릴리스가 방어자에게 도움이 되는지 아니면 해를 끼치는지 탐구하는 내용
- 해당 보고서 작성에 500개 조직에서 1,300만 개의 활성 자산에 영향을 미치는 60억개 이상의 취약점이 분석

##### 2.1.8. Prioritization to Prediction Volume 8 : Measuring and Minimizing Exploitability
- 악용 가능성 측정 및 최소화 는 실제로 악용 가능성을 측정 방법을 통해 취약점 악용가능성을 최소화
- 현재는 해당 파일을 확인할 수 있는 다이렉트 링크는 미존재

#### 2.2. 분석결과


#### 2.2.1. 모든 취약점 관리전략이 동일한 기준으로 적용하기 어려움
- Exploit Code로 취약점의 우선순위를 지정하는 것이 CVSS점수 기준보다 11배 더 효과적으로 활용가능
- Twitter에서 언급한 CVSS보다 훨씬더 나은 잡음비를 가지고 있음(2배 더 효과가 높음)
- 또한 취약점을 수정하는 대상을 증가하는 것보다 취약점의 우선순위를 개선하는 것이 효과적이며 2가지를 모두 수행하는 경우 취약점 영향도는 29배는 감소 가능

#### 2.2.2. Exploit의 영향도를 측정하는 기준 : EPSS(Exploit Prediction Scoring System활용
- EPSS는 CVE의 최신정보와 실제 악용데이터를 사용하여 취약점이 인터넷환경에서 악용되는 여부와 시기를 예측
- EPSS를 개선하고 시뮬레이션 한 결과 
 
#### [별첨]
18+ Threat Intel Feeds Power Modern Vulnerability Management [[Link]](https://www.kennasecurity.com/blog/15-plus-threat-intel-categories-to-power-modern-vulnerability-management/)
- Intelligence 자료를 수집하는 것이 좋기는 하지만 이걸 Architecture화해서 사용하는 부분이 정리가 잘 되어 있어서 수집
- 해당 Architecture를 바탕으로 EPSS 계산기 [[Link]](https://www.kennaresearch.com/tools/epss-calculator/) 및 산업별 EPSS 수치 참조
 
- EPSS 수치화 [[Link]](https://www.kennaresearch.com/benchmarking/)
- EPSS를 기반으로 산업별 Risk Score를 수치화한 자료(분기별로 확인 가능)
 

# [ 취약점 ]
---


### Jiushou - A data set of Ethereum Smart contract bugs [[Link]](https://github.com/xf97/JiuZhou?fbclid=IwAR0nU0HX4yb6_utEVXjjh1P2cnkWI_N250X_o04daw2uErpszsMTAB_PHaQ)
#### CVE-2022-21907
- Windows HTTP 프로토콜 원격 코드 실행 취약점 [[Link]](https://hackyboiz.github.io/2022/01/20/l0ch/2022-01-20/?fbclid=IwAR1SYcX6gsL5zXHJn64GPh1uN5LEPd2iAl1TE70xUlmbvZQZ4Dg-obFBjdI)
- 2022년 1월 Patch Tuesday에서 Windows의 http 메시지 파싱과 response 생성을 처리하는 HTTP.sys 드라이버에서 시스템 권한으로 원격 코드 실행이 가능한 취약점 패치

### Google Details Two Zero-Day Bugs Reported in Zoom Clients and Multimedia Router(MMR) Servers. [[Link]](https://thehackernews.com/2022/01/google-details-two-zero-day-bugs.html?fbclid=IwAR2D5pgppUN7qZEcjSPq2StvQx-xEX7JfcijBqeZMtr5SH358uF1D03UOBA)
#### CVE-2021-34423 (CVSS score: 9.8)
- A buffer overflow vulnerability that can be leveraged to crash the service or application, or execute arbitrary code.

#### CVE-2021-34424 (CVSS score: 7.5)
- A process memory exposure flaw that could be used to potentially gain insight into arbitrary areas of the product's memory.

# [ 도구 ]
---

#### dep-scan [[Link]](https://github.com/AppThreat/dep-scan)
- OSV, NVD, GitHub, NPM의 Vulnerability Data Source를 기반으로 레파지토리나 컨테이너 이미지를 스캔하여 공개된 취약성(CVE), 권고 및 라이선스 제한을 기반으로 하는 프로젝트 종속성 등을 감사할 수 있는 오픈소스 도구
 

# [ 기타 ]
---

- Windows Drivers Reverse Engineering Methodology [[Link]](https://voidsec.com/windows-drivers-reverse-engineering-methodology/?fbclid=IwAR1TTd7XFk9NO_x5Bps-_4HjOdSvFHDSReGHCoa-d58qsbIcqtNzy6s-ce4)

- Random Forests(TM) in XGBoost [[Link]](https://xgboost.readthedocs.io/en/latest/tutorials/rf.html?fbclid=IwAR2Ip0WDlferelEaMGiq2RJRRx3nF_iYtzBVva9fyubqSH_wWR1o2vsPOzc)

- Incident Response and Security Operations Fundamentals, by Blue Teams Academy [[Link]](https://www.blueteamsacademy.com/incident-response-and-security-operations-fundamentals/?fbclid=IwAR1xq3RTqEswzHZ63skIOihsy-LMmB1TVENTtw4s4fTvBLYiRTvVvf9Q8YE)

- IoT Device Infected #MoziBot IP List

- Cc @tiresearch1 [[Link]](https://github.com/ti-research-io/ti/commit/51bb178a1629f31ac87d43e38cbebe554f02e0a3?fbclid=IwAR3bf4rdXweymExcFZi8I3TJZ6Hr_yMVzCIh1TkCPnZI5wDwDxbK5RnUzzA)

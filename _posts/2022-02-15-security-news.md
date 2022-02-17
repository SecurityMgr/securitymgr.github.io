---
layout: post
title: 보안기사 이모저모
date: 2022-02-15 09:00:00 +0900
category: SecurityNews
---


# [ Security News ]
---
#### Microsoft Defender will soon block Windows password theft [[link]](https://www.bleepingcomputer.com/news/microsoft/microsoft-defender-will-soon-block-windows-password-theft/)
>- 개요 : Microsoft는 LSASS 프로세스에서 Windows 자격 증명을 도용하려는 시도를 Microsoft Defender 'Attack Surface Reduction'에서 차단하는 보안규칙을 활성화
- 자격증명 도용 탐지 방법
1. Windows LSASS(Local Security Authority Server Service)프로세스의 메모리 덤프 by Mimikatz
![이미지](https://github.com/SecurityMgr/securitymgr.github.io/blob/main/_img/2022/20220215_1.jpg)
2. Microsoft Defender의 ASR를 통해 자격증명도용탐지
- Anti-Virus설치시 ASR은 즉시 장치에서 비활성화되며 그렇지 않은 경우 ASR 구동
+ ASR : Windows 로컬 보안 기관 하위 시스템(lsass.exe)에서 자격 증명 도용 차단"의 기본 상태가 구성되지 않음에서 구성됨으로 변경되고 기본 모드 가 차단으로 설정
![이미지](https://github.com/SecurityMgr/securitymgr.github.io/blob/main/_img/2022/20220215_2.jpg)
 
#### [ Process Explorer가 LSASS 프로세스를 덤핑하지 못하도록 차단하는 ASR 규칙 ]
- 그러나 Defender는 경로를 허용 목록에 추가하므로 c:\Windows\Temp\cr0czrap\Extract\TrolleyExpress.exe에서 실행되는 모든 응용 프로그램은 lsass를 덤프가 가능
+ ASR 기능 분석 : https://github.com/commial/experiments/tree/master/windows-defender/ASR
![이미지](https://github.com/SecurityMgr/securitymgr.github.io/blob/main/_img/2022/20220215_3.jpg)

#### CISO들, 로그4j에 대해서 어떻게 설명할 것인가? [[link]](https://www.boannews.com/media/view.asp?idx=104763&fbclid=IwAR1Vxg0ki_uZzVyvNm7RKedNg5xRriPZiyDKM1FPGvo5dOOdbrjgK_rPAAM)
>- C레벨에서 Log4j취약점을 바라보는 포커싱에 대한 질문
1. 총 책임자 혹은 책임 조직은 누구인가?
2. 로그4j의 취약점이 우리 조직에 미칠 영향력을 제대로 이해하고 있는가?
3. 모든 자바 기반 애플리케이션들에 대한 가시성을 확보하고 있는가? 그러므로 잃을 수 있는 것들과 예상 피해 규모를 제대로 파악하고 있는가?
4. 이 사태를 해결해 나갈 인재와 자원, 도구, 예산을 충분히 확보하고 있는가?
5. 이 취약점으로 인해 공급망에도 영향이 있는가? 긴급 대처 계획이 있는가?
6. 복구 계획을 가지고 있는가? 그러면서 사업 연속성을 확보할 수 있는가?

# [ Report ]
---
#### [KISA Insight 2022 Vol.01] 2030 미래사회 변화 및 ICT 8대 유망기술의 사이버 위협전망 [[link]](https://www.kisa.or.kr/20301/form?postSeq=9&page=1&fbclid=IwAR2ML9RIjHYHfhNWrQjPbwRKjkxt3CORSQAcI5mrvW-s0MgtlEtYZGlZpFo)
>- 최근 이슈가 되는 보안토픽 8가지를 PEST관점으로 분류하여 나온 보고서로 매우 굿!!!★★★★★
+ 2030 미래사회 변화에 가장 많이 영향을 미치며 중요하다고 전망되는 ICT 8대 유망기술을 선정 
- “AI, IoT, 클라우드, 차세대 네트워크, 빅데이터, 블록체인, 메타버스, 디지털 트윈”
+ 유망 기술의 공급자 측 위협보다 이용자 측 위협이 높고 미래위협이 증가 
- 공급자ㆍ이용자 측면 모두에서 AI, 디지털 트윈, 메타버스, 빅데이터 기술 중심으로 위험도가 증가하며 현재보다 미래위협이 높게 나타남
- 또한 이들 기술의 위험 대응준비 수준도 낮아 관련 보안 기술개발 등을 추진해야 할 것으로 보임

#### [2022년 1월] 인터넷·정보보호 법제동향 제172호 [[link]](https://www.kisa.or.kr/20201/form?postSeq=191&page=1&fbclid=IwAR1WSpdnnWMwtwnHzn-QfPBABLXz6kYQI5JdT5ZnemYBePl2AggmQBDkvcU#fnPostAttachDownload)
##### 공포된 법령
>- 「산업 디지털 전환 촉진법」 제정법률 공포 (2022. 1. 4.)
- 「인터넷주소자원에 관한 법률」 일부개정법률 공포 (2022. 1. 11.)
- 「자율주행자동차 상용화 촉진 및 지원에 관한 법률 시행령」 일부개정령 공포 (2022. 1. 28.)
- 「클라우드컴퓨팅 발전 및 이용자 보호에 관한 법률」일부개정법률 공포 (2022. 1. 11.)
##### 국회 제출 법률안
>- 「정보통신망 이용촉진 및 정보보호 등에 관한 법률」 일부개정법률안(배현진의원 대표발의, 2022. 1. 13. 제안)
- 「정보통신망 이용촉진 및 정보보호 등에 관한 법률」 일부개정법률안(배현진의원 대표발의, 2022. 1. 14. 제안)
- 「가상융합경제 발전 및 지원에 관한 법률」 제정법률안(조승래의원 대표발의, 2022. 1. 25. 제안)
- 「조세특례제한법」 일부개정법률안(조승래의원 대표발의, 2022. 1. 25. 제안)
- 「지방세특례제한법」 일부개정법률안(조승래의원 대표발의, 2022. 1. 25. 제안)
- 「메타버스산업 진흥법」 제정법률안(김영식의원 대표발의, 2022. 1. 11. 제안)
- 「공직선거법」 일부개정법률안(민형배의원 대표발의, 2022. 1. 17. 제안)
- 「신문 등의 진흥에 관한 법률」 일부개정법률안(조명희의원 대표발의, 2022. 1. 26. 제안)
- 「아동·청소년의 성보호에 관한 법률」 일부개정법률안(강선우의원 대표발의, 2022. 1. 18. 제안)
- 「지능정보화 기본법」 일부개정법률안(김예지의원 대표발의, 2022. 1. 21. 제안)
##### 해외 입법 동향
##### 미국
>- 미국 상원, 공공 부문 사이버보안 역량 강화를 위한 「공급망 보안 교육법(안)」과 「주정부 및 지역정부 사이버보안법(안)」 통과 (2022. 1. 11.)
- 미국 하원, 웹사이트 서비스 약관에 대한 이용자의 이해도 향상을 위한 「서비스 약관 표시, 디자인 및 가독성에 관한 법률(안)」 발의 (2022. 1. 13.)
- 미국 연방통신위원회, 통신사업자 고객 데이터 침해 시 보고 의무를 강화한 규칙 개정안 입법예고(NPRM) 검토 착수 (2022. 1. 13)
- 미국 하원, 소비자를 대상으로 한 표적 광고를 금지하는 「표적 광고 금지법(안)」 발의 (2022. 1. 18.)
- EU집행위원회, 플랫폼 종사자를 피고용자로 추정하는 기준을 제시한 「플랫폼 근로에서의 근로 여건 개선에 관한 지침(안)」 발표 (2021. 12. 9.)

##### 아일랜드
>- 아일랜드 정부, 방송 및 온라인 비디오 서비스 통합 규제기관 신설을 위한 「온라인 안전 및 미디어 규제법(안)」 발표 (2022. 1. 12.)

##### 대만
>- 대만 정부, 디지털 혁신 및 사이버보안을 담당하는 정부 조직을 신설하는 「디지털발전부 조직법」 공포 (2022. 1. 19.)

##### 해외 단신
##### 호주
>- 호주 정부, 사이버폭력 피해 방지를 위한 「온라인 안전법 2021」 시행 (2022. 1. 22.)


# [ SOC, Security Operation Center ]
---
#### Automotive SOC vs. SOC: What is the Difference? [[link]](https://argus-sec.com/automotive-soc-vs-soc/)
>- Automotive SOC (‘ASOC’ or Automotive Security Operation Center)
![이미지](https://github.com/SecurityMgr/securitymgr.github.io/blob/main/_img/2022/20220215_4.jpg)

# [ Cloud ]
#### Container Security Checklist: From the image to the workload [[link]](https://github.com/krol3/container-security-checklist?fbclid=IwAR3mlFX4zdNiiYmnL4e9-7MmcnT_aVEALDkoPQyVPcvnabKBY-FBLj8JVu4)
>- Container Threat Model과 Container Security Checklist를 제공
1. Container Threat Model By Container Security by Liz Rice
- Released April 2020에 출발된 ‘Container Security’의 내용 중 일부
- URL : https://medium.com/oreillymedia/container-security-threats-38649261fb4f
- Threat Vector : Insecure Host, Misconfiguration container, Vulnerable application, Supply chain attacks, Expose secrets, Insecure networking, Integrity and confidentiality of OS images, Container escape vulnerabilities
![이미지](https://github.com/SecurityMgr/securitymgr.github.io/blob/main/_img/2022/20220215_5.jpg)
 
#### Container attack vendors
2. Container Security Checklist
- Phases : Secure the Build > Secure the Container Registry > Secure the Container Runtime > Secure the Infrastructure > Secure the Data > Secure the Workloads
![이미지](https://github.com/SecurityMgr/securitymgr.github.io/blob/main/_img/2022/20220215_6.jpg)
3. Contents
- Cloud Native Concepts
- Container Threat Model
- Container Security Checklist
- Secure the Build
	+ Secure Supply Chain
	+ Hardening Code - Secure SDLC (Software Development Life Cycle)
	+ Secure the Image - Hardening
	+ Image Scanning
	+ Image Signing
- Secure the Container Registry
	+ Registry Resources
- Secure the Container Runtime
	+ Why is important Runtime Security?
	+ Constraints
	+ Docker Security
- Secure the Infrastructure
- Secure the Data
	+ Secrets Management Tools
- Secure the Workloads... Running the containers
- Container Security Guides
- Further reading:
- Collaborate


# [ ETC ]
---
#### DFIRDIVA [[link]](https://training.dfirdiva.com/listing-category/incident-response)
>- 포렌식 및 침해사고 등 관련 참고자료 아카이브
![이미지](https://github.com/SecurityMgr/securitymgr.github.io/blob/main/_img/2022/20220215_7.jpg)

#### BigQuery SQL Injection Cheat Sheet [[link]](https://ozguralp.medium.com/bigquery-sql-injection-cheat-sheet-65ad70e11eac)
>- Google BigQuery : Google Cloud의 페타바이트급 규모의 경제적인 완전 관리형 분석 데이터 웨어하우스
- BigQuery의 쿼리형태가 기존의 레거시 환경에서 사용하는 쿼리랑 일부 처리방법이 상이
![이미지](https://github.com/SecurityMgr/securitymgr.github.io/blob/main/_img/2022/20220215_8.jpg)
- 마지막에 Cheat Sheet때문에 다시한번 정리

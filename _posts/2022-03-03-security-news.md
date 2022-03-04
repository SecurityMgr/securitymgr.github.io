---
layout: post
title: 보안기사 이모저모
date: 2022-03-03 09:00:00 +0900
category: SecurityNews
---


# [ Security News ]
---
#### Conti Ransomware source code leaked by Ukrainian researcher [[link]](https://www.bleepingcomputer.com/news/security/conti-ransomware-source-code-leaked-by-ukrainian-researcher/?fbclid=IwAR0ROlbB2aJ6T3P7uPHHQ-O_BEuNzFC0MiNKIEQ8HAnB-xGQp9F1_rEwsCc)
- 우크라이나의 한 연구원이 우크라이나 침공에 대한 러시아 우호적 발언을 한 Conti랜섬웨어에 대한 보복(?)으로 @ContiLeaks을 통해 정보유출
- Conti 및 Ryuk랜섬웨어의 개인 XMPP채팅서버에서 유출한 6만여개의 내부 메시지가 포함된 393개의 JSON파일 유출
- Conti 랜섬웨어 암호화 기능, 암호해독기 및 빌더 소스코드가 포함된 아카이브 파일 공유
![이미지](https://github.com/SecurityMgr/securitymgr.github.io/blob/main/_img/2022/220303_1.jpg?raw=true)

#### Elections GoRansom – a smoke screen for the HermeticWiper attack [[link]](https://securelist.com/elections-goransom-and-hermeticwiper-attack/105960/?fbclid=IwAR0R9PDXuTkzwZSP_AecNdR0hqVaizmeAZQh6lhus5k1_7GoAZ62jRmmK3Q)
- Elections GoRansom(일명 HermeticRansom)라고 하는 랜섬웨어 분석정보 공유
- 해당 랜섬웨어 제작자는 미국 대통령선거와 관련된 함수이름지정체계를 사용
- 난독화도 없으며 간단한 기능만 적용

#### CISA Warns of High-Severity Flaws in Schneider and GE Digital's SCADA Software [[link]](https://thehackernews.com/2022/02/cisa-warns-of-high-severity-flaws-in.html?fbclid=IwAR3Xo3ubZNjxEPmMdB4kp2nZO7QMhHzQwjSDh6LtZDd1_rCG1Q_acO5PVT4)
- 미국 사이버 보안 및 기반시설 보안국(CISA)에서 슈나이더 일렉트릭의 Easergy 취약점 권고
	1. CVE-2022-22722 (CVSS score: 7.5) – Use of hardcoded credentials that could be abused to observe and manipulate traffic associated with the device.
	2. CVE-2022-22723 and CVE-2022-22725 (CVSS score: 8.8) – A buffer overflow vulnerability that could result in program crashes and execution of arbitrary code by sending specially crafted packets to the relay over the network.

#### TeaBot Android Banking Malware Spreads Again Through Google Play Store Apps [[link]](https://thehackernews.com/2022/03/teabot-android-banking-malware-spreads.html?fbclid=IwAR1mVpx0fJ2OHiWnoLOE8FKm85ZynFiJdrnhat92fQodOiFhutujRNmRKgw)


# [ Reports ]
---
#### 2021년 하반기 악성코드 은닉사이트 탐지 동향 보고서 [[link]](https://www.boho.or.kr/data/reportView.do?bulletin_writing_sequence=36472&fbclid=IwAR0gnVUVOT_mcQXg-D2Hre0qcpnaOFGRS-ClS_JerXxHwgxycAtYoiXs3rM)
![이미지](https://github.com/SecurityMgr/securitymgr.github.io/blob/main/_img/2022/220303_2.png?raw=true)

# [ Tools ]
---
#### BruteShark - Network Analysis Tool [[link]](https://www.kitploit.com/2022/03/bruteshark-network-analysis-tool.html?fbclid=IwAR0hXN_fas3VmREEFYtEnjBKrEUbAEo_-5nItAE7tfBHm-xD64cab6n2hPw)
+ 주요기능
	- 사용자 이름 및 암호 추출 및 인코딩(HTTP, FTP, Telnet, IMAP, SMTP...)
	- 인증 해시를 추출 하고 Hashcat(Kerberos, NTLM, CRAM-MD5, HTTP-Digest...)을 사용하여 해독
	- 시각적 네트워크 다이어그램 구축(네트워크 노드, 열린 포트, 도메인 사용자)
	- DNS 쿼리 추출
	- 모든 TCP 및 UDP 세션 재구성
	- 파일 조각(File Carving)
	- VoIP 통화 추출(SIP, RTP)
![이미지](https://github.com/SecurityMgr/securitymgr.github.io/blob/main/_img/2022/220303_3.png?raw=true)


# [ Vulnerability ]
---
#### CVE-2022-21971: Uninitialized pointer free in prauthproviders [[link]](https://github.com/0vercl0k/CVE-2022-21971?fbclid=IwAR2eWwKRH7_6Sr0rDln5JOU2h8BqHDLuK_fdTB40xPRk9wai3bHghr58csg)

#### CVE-2022-24086 Magento RCE [[link]](https://reconshell.com/cve-2022-24086-magento-rce/)
+ 영향받는 버전 : Adobe Commerce versions 2.4.3-p1 (and earlier) and 2.3.7-p2 (and earlier)
![이미지](https://github.com/SecurityMgr/securitymgr.github.io/blob/main/_img/2022/220303_4.png?raw=true)

 

# [ Malware ]
---
#### Cybereason vs BlackCat Ransomware
+ 공격대상 : 통신, 상업 서비스, 보험, 소매, 기계, 제약, 운송 및 건설
+ 공격국가 : 미국, 독일, 프랑스, 스페인, 필리핀, 네덜란드
+ BlackCat 운영방법 : RaaS모델 운영방법으로 Cybercrime forums (ramp_v2, exploit.in)에서 “alphv”, “ransom”이름으로 제휴자 모집
+ 동작방법
	- Windows 및 Linux환경에서 동작가능하며 가상머신 내 동작여부 등 결정 가능
	- 감염된 시스템의 모든 로컬 디스크 파티션 및 숨겨진 파티션을 마운트하여 더 많은 파일 암호화 시도
	- 감염된 시스템의 기본 프로파일링 정보를 수집하여 C2에 업로그
		ㄴ 수집정보 : 화면캡처, 사용자이름, OS이름, OS언어, 시간대, 윈도우 UUID, 키보드 언어, 설치된 사용자, 설치된 소프트웨어, 드라이브
	- 일부 코드에서 LockBit 런처와 유사성이 발견
![이미지](https://github.com/SecurityMgr/securitymgr.github.io/blob/main/_img/2022/220303_5.jpg?raw=true)


# [ ETC ]
---
![이미지](https://github.com/SecurityMgr/securitymgr.github.io/blob/main/_img/2022/220303_6.png?raw=true)

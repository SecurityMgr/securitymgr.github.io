---
layout: post
title: 보안기사 이모저모
date: 2022-02-21 09:00:00 +0900
category: SecurityNews
---


# [ Security News ]
---
#### 악성코드 개발에 유용한 라이브러리들 _[[link]](https://hackyboiz.github.io/2022/02/20/idioth/useful_libs_for_malware_dev/?fbclid=IwAR1whsT36JYNih53w9ocvuBJE7gmTv3RaiL82yw-AcNn9VtcNXTU4cFcTsI)

#### 美 법무부, 북·이란 겨냥 '가상화폐 범죄' 전담국 신설(종합) [[link]](https://www.yna.co.kr/view/AKR20220218007600071?input=1195m&fbclid=IwAR3fYr99gEWk9SNmf5h__oCz7U_AjvNrgOv3dJsFE14ljdo-yj47qYFmMrI)
- 전담국에서는 사이버 사기 위험에 범부처 차원에서 대응하기 위해 추진
- 가상화폐부터 사이버 범죄, 돈 세탁 등 전방위에 걸친 수사 역량을 결집하는 거점으로 기능할 예정

#### U.S. Cybersecurity Agency Publishes List of Free Security Tools and Services [[link]](https://thehackernews.com/2022/02/us-cybersecurity-agency-publishes-list.html?fbclid=IwAR1xPDUJqo3bHKMedRH-EiDkxgLHo5dSlcq315GpMFi1AnECEEg6JPu5wEQ)
+ 개요
- 미국 CIA에서 주요 인프라의 사이버보안위험 감소를 위한 목적으로 사이버보안 도구 및 서비스 목록 공유
+ 기본조치
> 1. 소프트웨어 보안결함 수정 : KEV(Known Exploited Vulnerabilities)카탈로그 참조하여 SW공급업체에서는 최신버전으로 업데이트 권고
2. 다단계 인증(MFA)구현
3. 나쁜관행 중단 : 단종SW교체, 알려진/기본값/변경 불가능한 암호에 의존하는 모든 시스템 또는 제품 교체, 중요시스템 및 리소스 원격 접근 MFA 적용
4. CIA의 사이버 취약점 스캔에 등록 : 국내에 KISA에서 중소기업 신청자에 한해 보안진단해주는 서비스와 유사
5. SOS(Stuff Off Search) : 공격표면 확인용 검색요청

+ 주요목적
#### 사이버보안사고 발생가능성 감소, 악성활동 신속하게 탐지, 사건에 대한 효율적 대응, 회복탄력성 극대화
#### (CISA LAUNCHES NEW CATALOG OF FREE PUBLIC AND PRIVATE SECTOR CYBERSECURITY SERVICES) [[link]](https://www.cisa.gov/news/2022/02/18/cisa-launches-new-catalog-free-public-and-private-sector-cybersecurity-services)

#### FREE CYBERSECURITY SERVICES AND TOOLS [[link]](https://www.cisa.gov/free-cybersecurity-services-and-tools)
+ Tools[[link]](https://www.cisa.gov/free-cybersecurity-services-and-tools)
	> - Reducing the Likelihood of a Damaging Cyber Incident
	- Take Steps to Quickly Detect a Potential Intrusion
	- Ensure That The Organization is Prepared to Respond if an Intrusion Occurs
	- Maximize the Organization's Resilience to a Destructive Cyber Incident
	

# [ Vulnerability ]
---
#### CVE-2022-23131 : Zabbix SAML Authentication Bypass [[link]](https://blog.sonarsource.com/zabbix-case-study-of-unsafe-session-storage?fbclid=IwAR2JoUQJNssYaCSw8gUba01uYF2DiP3Ua5Dbl4Oj5KAx0QNLLaeccV7AYFA)
+ 개요
	- Zabbi 클라이언트의 세션구현에서 전체 네트워크의 손상으로 이어질 수 있는 심각도 높은 취약점 발견(CVE-2022-23131)
	* Zabbix : 인프라의 CPU부하 및 네트워크 트래픽과 같은 매트릭을 수집하여 중앙집중화하여 추적이 가능하게 하는 OSS플랫폼
	- SAML SSO인증이 활성화된 경우 인증을 우회하고 관리자 권한 획득 가능
	- CVE-2021-46088을 사용하여 연결된 Zabbix서버 및 Zabbix 에이전트 인스턴스 모두에서 임의의 명령 실행 가능
+ 대상 : Zabbix Web Frontend 5.4.8, 5.0.18 및 4.0.36 포함
+ 대응방안 : Zabbix Web Frontend 실행하는 인스턴스를 6.0.0beta2, 5.4.9, 5.0.19또는 4.0.37로 업그레이드
+ 취약점 분석
	- 모니터링 플랫폼인 Zabbix는 일반적으로 4가지 고유한 구성요소를 통해 인프라에 배포
	1. Zabbix Agent : 모니터링되는 모든 노드에서 실행되는 서비스, Zabbix서버에서 요청할 때 정보 수집
	2. Zabbix Server : 모니터링 데이터를 수집하고 구성된 임계값에 도달하면 경고 발생위해 Zabbix Agent에 연결
	3. Zabbix Proxy : 단일 Zabbix서버를 수백개의 Zabbix  Agent에 연결하는 것은 비용 및 일부 네트워크 토콜로지 배포에 어려움을 겪게 할 수 있음
	Zabbix Proxy인스턴스는 전체 영역의 데이터를 중앙 집중화하고 수집된 데이터를 기본 Zabbix Server에 보고하는 것이 목표
	4. Zabbix Web Frontend : Zabbix서버에 대한 인터페이스, TCP 및 공유 데이터베이스와 통신
	대시보드를 통해 시스템 관리자가 수집된 데이터의 모니터링 및 Zabbix서버 구성에 사용(예: 호스트 나열, Zabbix Agent에서 스크립트 실행)
+ 동작구성도
![이미지](https://github.com/SecurityMgr/securitymgr.github.io/blob/main/_img/2022/220221_1.png?raw=true)

#### CVE-2022-23131 - SAML SSO 인증 우회
- SAML(Security Assertion Markup Language)은 가장 일반적인 SSO(Single-Sign-On) 표준 중 하나로 XML을 중심으로 구현되어 ID 제공자(IdP, 사용자를 인증할 수 있는 엔티티)가 서비스 제공자(SP, 여기서는 Zabbix)에게 사용자를 제공
- SAML을 통해 사용자 인증이 허용되도록 Zabbix웹프론트엔드를 구성이 가능하나 ID공급자의 세부정보를 알아야 하기 때문에 기본적으로 비활성화
- CEncryptedCookieSession::checkSign()메서드는 CEncryptedCookieSession:: extractSessionId ()에서만 호출되지만 CCookieSession메서드에서는 호출되지 않으며, sessionid 이외의 필드에 접근할 때 세션 신뢰성 검증이 없음
- Zabbix Web Frontend가 Admin이라는 높은 권한을 가진 사용자로 자동구성되면서 공격자는 연결된 모든 Zabbix Server에서 임의명령 실행이 가능
ㄴ AllowKey=system.run[*] (Default값이 아님)으로 구성에서 명시적으로 허용되는 경우 Zabbix Agent에서는 임의명령 실행이 가능

#### Advisory: Cisco RV340 Dual WAN Gigabit VPN Router (RCE over LAN) [[link]](https://www.iot-inspector.com/blog/advisory-cisco-rv340-dual-wan-gigabit-vpn-router-rce-over-lan/?fbclid=IwAR15YUQ_Qx89e5E2V8vxZRJNlcFpSu7B6bY-dCev3i8cQSglrhvhVl5gXJQ)
- Affected vendor & product Vendor Advisory	Cisco RV340 Dual WAN Gigabit VPN Router [[link]](https://www.cisco.com/c/en/us/support/docs/csa/cisco-sa-smb-mult-vuln-KA9PK6D.html)
- Vulnerable version : 1.0.03.24 and earlier
- Fixed version	: 1.0.03.26
- CVE IDs : 
	> CVE-2022-20705
	CVE-2022-20708
	CVE-2022-20709
	CVE-2022-20711
- Impact : 10 (critical) AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H
- Credit Q. Kaiser, IoT Inspector Research Lab


# [ Malware ]
---
#### Highway to Conti: Analysis of Bazarloader [[link]](https://elis531989.medium.com/highway-to-conti-analysis-of-bazarloader-26368765689d)
- 2020년 4월에 최초 관찰되고 ITG23 또는 TrickBot gang라는 그룹에서 개발된 것으로 알려진 BazarLoader악성코드 분석내용
- 로더는 PowerShell, Mshta, ISO파일과 같은 배포시에 LoLbin을 사용하여 Rundll32나 Regsvr32를 통한 캠페인으로 배포
- SHA1 hash: 94114c925eff56b33aed465fce335906f31ae1b5

# [ Tools ]
---
#### TheHarvester – OSINT Suite To Track Digital Footprints [[link]](https://hackersonlineclub.com/theharvester-osint-suite-to-track-digital-footprints/?fbclid=IwAR05iAumlV37wyMW-h8p9jTZCDkQWwuqG24cILWBMTh3dJ596TSY2l9Bq1I)
- Google, Google Profiles등의 OSINT정보를 검색
	> + Google – emails, subdomains
	+ Google profiles – Employee names
	+ Bing search – emails, subdomains/hostnames, virtual hosts
	+ Pgp servers – emails, subdomains/hostnames
	+ LinkedIn – Employee names

#### Voltron - A Hacky Debugger UI For Hackers [[link]](https://www.kitploit.com/2022/02/voltron-hacky-debugger-ui-for-hackers.html?fbclid=IwAR3s5yHBO3TOmDgX0BLsyKYgCHh6VbPLCbe8hJ72c5ZNnb5p74CZP7e9MI8)
- 다양한 디버거(LLDB, GDB, VDB 및 WinDbg)들의 Python으로 확장 가능한 디버깅 UI툴킷
![이미지](https://github.com/SecurityMgr/securitymgr.github.io/blob/main/_img/2022/220221_2.png?raw=true)

#### HybridTestFramework - End To End Testing Of Web, API And Security [[link]](https://www.kitploit.com/2022/02/hybridtestframework-end-to-end-testing.html?fbclid=IwAR10GJLfC7U0zSr1lPjHiIGpVKZSx4IQn49oL9t8s7MgBi1H0voHM5cpalU)
- 소프트웨어 테스팅 지원 플랫폼(CI/CD구현을 위해서는 이런 플랫폼이 중요)
![이미지](https://github.com/SecurityMgr/securitymgr.github.io/blob/main/_img/2022/220221_3.png?raw=true)

#### jadx - Dex to Java decompiler [[link]](https://github.com/skylot/jadx)
- Android Dex 및 Apk 파일에서 Java 소스 코드를 생성하기 위한 명령줄 및 GUI 도구
![이미지](https://github.com/SecurityMgr/securitymgr.github.io/blob/main/_img/2022/220221_4.png?raw=true)

#### GitHub code scanning now finds more security vulnerabilities [[link]](https://www.bleepingcomputer.com/news/security/github-code-scanning-now-finds-more-security-vulnerabilities/?fbclid=IwAR2jq9X7-Tsx2aqfO9uC7oJql0hXHUOuHXBPfY_cyfX3QupEIWPCGkxMUbk)
GitHub에 머신러닝 기술을 기반으로 코드 취약점을 스캔할 수 있는 기능이 추가되었습니다.
현재는 JavaScript 및 TypeScript로 작성된 repository만 지원하는 것으로 보아 실험적인 기능으로 보여집니다.
repository 별 이용 정책은 다음과 같습니다.
- Public repository : 무료
- Private repository : 엔터프라이즈만 사용 가능
![이미지](https://github.com/SecurityMgr/securitymgr.github.io/blob/main/_img/2022/220221_5.png?raw=true)
 

# [ ETC ]
---
금융보안원은 금융데이터거래소(FinDX) 운영 2년차를 맞이하여 그간의 운영 현황을 분석하고 중점 업무 추진방향을 수립하였습니다.
출범 이후 현재까지 금융데이터거래소에는 106개 기업이 회원사로 참여하여 985개 데이터 상품 등록 및 7,601건 거래가 이루어졌으며,
금년에는 
	>1. 금융‧민간 데이터댐과 협력하여 다양한 가명‧익명 데이터 발굴‧공급, 
	2. 데이터 반출없이 안전하게 분석할 수 있는 샌드박스 분석서비스 강화, 
	3. 데이터 혁신 얼라이언스를 통한 협력‧동반성장 도모, 
	4. 시장 니즈를 반영한 플랫폼 운영 등을 중점 추진할 예정입니다.

금융권에서 생존과 미래 경쟁력 확보를 위한 양질의 데이터 확보가 더욱 중요해지고 있는만큼 앞으로도 금융보안원은 금융산업과 시장의 니즈와, 금융당국의 정책 방향에 맞춰 금융데이터거래소(FinDX)를 지속 운영해 나가겠습니다.
![이미지](https://github.com/SecurityMgr/securitymgr.github.io/blob/main/_img/2022/220221_6.png?raw=true)

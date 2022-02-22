---
layout: post
title: 보안기사 이모저모
date: 2022-02-22 09:00:00 +0900
category: SecurityNews
---


# [ Security News ]
---
#### 클라우드가 그리 좋다는데, 왜 지금 상황은 그렇지 못한가? [[link]](https://www.boannews.com/media/view.asp?idx=104920&fbclid=IwAR3BPqbYB1IGhHQc3WRIVoiztSnwvNw5vIQ-1SruRXneBe09E6OUsvVMyqo)
1. 온프레미스에서 새는 바가지, 클라우드에서도 샌다
	- 클라우드 마이그레이션시에는 클라우드 환경에 맞게 업무 프로세스 및 규정, 데이터관리 체계등의 변화가 필요
	- 클라우드 보안에서 가장 중요한 IAM은 클라우드 네이티브 인증 및 접근 프로세스 도입 시 가장 중요
2. ‘설계 단계에서부터 보안’은 아직 보편화되지 않았다
	- Security by Design이 반영되지 않은 환경은 CI/CD 파이프라인이나 컨테이너 레지스트리 등에서 취약점으로 연계
3. 리스크에 대한 개념 역시 변화해야 한다
	- 취약점을 ‘리스크 관리’의 요인으로 핸들링하여 모든 취약점을 패치한다는 것 보다는 관리를 통한 가시성 확보관점으로 접근
	- CVE, CWE관점을 넘어 PoC존재여부에 따라 리스크를 정량화가 가능하도록 Exploit의 영향도를 측정하는 기준인EPSS(Exploit Prediction Scoring System)활용
	(위의 내용은 일전에 Apache Log4j 취약점 패치에 대한 연속적 취약점 보고의 실무적 관점을 반영한 뉴스기사에서 차용)

#### Hackers Exploiting Infected Android Devices to Register Disposable Accounts [[link]](https://thehackernews.com/2022/02/hackers-exploit-bug-in-sms-verification.html?fbclid=IwAR1k1sk9kdhM2hjrmGzcXFHCmj5frRipCPtkIEJKcYrbEIyfbD9njF6mXn8)
- Reference: https://www.trendmicro.com/en_us/research/22/b/sms-pva-services-use-of-infected-android-phones-reveals-flaws-in-sms-verification.html
- SMS PVA(전화 인증 계정) 서비스를 분석한 결과 수천 대의 감염된 Android 전화가 포함된 봇넷 위에 구축된 악성 플랫폼이 발견
* SMS PVA서비스 : 다른 온라인 서비스 및 플랫폼에 등록하는데 사용할 수 있는 대체 휴대폰 번호를 사용자에게 제공하고 SMS기반 인증 및 확인을 위해 배치된 SSO 매커니즘
- smspva[.]net이라는 특정 서비스는 SMS 가로채기 맬웨어에 감염된 Android 기기로 구성
![이미지](https://github.com/SecurityMgr/securitymgr.github.io/blob/main/_img/2022/220222_1.jpg?raw=true)
 

#### Qbot and Zerologon Lead To Full Domain Compromise [[link]](https://thedfirreport.com/2022/02/21/qbot-and-zerologon-lead-to-full-domain-compromise/?fbclid=IwAR1S6stFBqjcM2bgfmN5O76wYkBZiGvxMeUQrm7xi19hGpKm19NzLOHm7hI)
MITRE기반으로 Qbot (a.k.a. Quakbot/Qakbot)과 Zerologon 취약점(CVE-2020-1472)을 이용한 공격분석에 대한 설명
- 개요
	+ Qbot (a.k.a. Quakbot/Qakbot)과 Zerologon 취약점(CVE-2020-1472)로 도메인 관리자 권한 획득
- Timeline
![이미지](https://github.com/SecurityMgr/securitymgr.github.io/blob/main/_img/2022/220222_2.png?raw=true) 


- 공격 상세분석
	>1. Initial Access
		+ Qbot은 악성DLL을 다운로드 하는 악성문서를 통해 이메일로 전달
		+ Reference : [[link]](https://tria.ge/211115-r554waafe6)
		![이미지](https://github.com/SecurityMgr/securitymgr.github.io/blob/main/_img/2022/220222_3.jpg?raw=true)
		
	2. Execution
		+ QBot PowerShell을 통해 아래 이벤트들이 시작
		+ 예약된 작업에서 HKCU:\SOFTWARE\Pvoeooxfbase64로 인코딩된 값을 포함하는 3개의 키값이 생성된 것을 확인
		![이미지](https://github.com/SecurityMgr/securitymgr.github.io/blob/main/_img/2022/220222_4.jpg?raw=true)
	3. Persistence
		+ Scheduled Task/Job – Scheduled Task On Beachhead
	4. Privilege Escalation
		+ Zerologon(CVE-2020-1472)를 이용해 도메인 권한 탈취
		![이미지](https://github.com/SecurityMgr/securitymgr.github.io/blob/main/_img/2022/220222_5.png?raw=true)
	5. Defense Evasion
		+ 초기에 dll을 실행하면 QBot은 Process hollowing로 explorer.exe(32bit) 인스턴스를 시작한 다음 프로세스가 악성dll을 Injection
		<pre>
		<code>
		* Process hollowing : Process Replacement, RunPE, Process Injection등 다양한 이름으로 불리며, 악성코드가 대상 프로레스를 멈춤 상태로 실행시킨 다음 악성코드가 자신을 Inejction하는 방식으로 진행
		ㄴ Injection이후에는 대상 프로세스 실행 상태로 변경하여 악성코드를 실행
		ㄴ NtUnmapViewOfSection은 선택 사항이며 LoadLibrary(), CreateRemoteThread()를 사용하지 않음
		ㄴ 흐름 : CreateProcess → NtUnmapViewOfSection → VirtualAlloc → WriteProcessMemory → SetContextThread → ResumeThread
		Reference : [[link]](https://rninche01.tistory.com/entry/Dropper-3-2Process-Hollowing)
		</code>
		</pre>
		+ Beachhead의 Over-Pass-the-Hash을 사용하여 도메인 컨트롤러의 TGT를 요청
	6. Discovery
	7. Lateral Movement
		+ Cobalt Strike Beacons을 통해서 이동
	8. Command and Control
	9. Exfiltration

- MITRE MAP
![이미지](https://github.com/SecurityMgr/securitymgr.github.io/blob/main/_img/2022/220222_6.png?raw=true)

# [ Tools ]
---
#### MISP/misp-wireshark [[link]](https://github.com/MISP/misp-wireshark?fbclid=IwAR30dMKnGFyCB_up7Pb-bzfRh8ICOMVHaA2m1bzk3se2s-ztFhsGmjgC4Tc)
- 위협인텔리전스 분석플랫폼 MISP에 wireshark플러그인 릴리즈
![이미지](https://github.com/SecurityMgr/securitymgr.github.io/blob/main/_img/2022/220222_7.png?raw=true)

# [ ETC ]
---
#### K-CTI 2022, 2022 대한민국 사이버위협 침해사고대응 인텔리전스 컨퍼런스 BY 데일리시큐 [[link]](https://www.dailysecu.com/form/register.html?form_id=1639440295&fbclid=IwAR0CN6XM_19Vv6Myrvo5JW8SZpF6JjSwzjncmvsNP-QvWcL17lCaW_RYeAY)
- 2월 21일 진행된 컨퍼런스이며 1개를 제외한 발표자료들이 공개된 상태
- 표기되어 있는 1, 2, 4, 6, 10의 발표자료 내용들이 참고할만 하며, 인텔리전스의 취지에 가장 부합하는건 스틸리언 자료인듯
- 프로그램
	1. 국내 사이버 위협 사례 중 타깃형 워터링홀 공격의 위협 분석 내용과 위협추적-한국인터넷진흥원 종합분석팀 이태우 선임
	1. 하이브리드 환경에 적용 가능한 보안 전략-아카마이 박영열 상무-
	1. 어서와 인텔리전스는 처음이지?-한국 레코디드 퓨처 윤광택 인텔리전스 본부장-
	1. 랜섬웨어 공격그룹 별 악성코드 및 주요 동향-S2W 류소준 책임연구원/ 정영현 연구원-
	1. 정부기관 후원 해킹조직의 사이버위협 사례발표-이스트시큐리티 문종현 이사-(자료비공개)
	1. Log4J 공격 보안위협 사례 분석-엑사비스 이시영 대표-
	1. 위협 인텔리전스 실무, 공격의 탐지와 대응 시스템 구현-카스퍼스키 강민석 이사-
	1. 멀티 벡터 위협 탐지 및 대응과 인텔리전스의 활용-트렌드마이크로 윤명익 이사-
	1. 오픈소스 기반 툴들을 해킹 활동에 응용한 해킹 그룹들-NSHC 장영준 수석-
	1. 취약점에 대한 접근 방식의 변화 및 인텔리전스 서비스 발전 방향-스틸리언 신동휘 부사장-
	1. OSINT를 활용한 Attack Surface 위협 모니터링-익스웨어랩스 윤영 대표-
![이미지](https://github.com/SecurityMgr/securitymgr.github.io/blob/main/_img/2022/220222_8.jpg?raw=true)
 

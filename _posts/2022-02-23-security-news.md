---
layout: post
title: 보안기사 이모저모
date: 2022-02-23 09:00:00 +0900
category: SecurityNews
---


# [ Security News ]
---
#### 대선 2주 앞으로! 외교·안보·국방 분야 타깃 北 해킹 공격 주의보 [[link]](https://www.boannews.com/media/view.asp?idx=104989&kind=&fbclid=IwAR111zU4ZfgfQwavpUbsrQOxp6a7d9ywZxCR5-LCcJun1SGj7C8c_m9-das)
- 외교·안보·국방 분야 교수 및 민간전문가 겨냥한 북한발 APT 공격 지속
- 강의 및 기고문 작성에 필요한 프로필 양식 작성으로 악성문서 열람 유도

#### As Ransomware Payments Continue to Grow, So Too Does Ransomware’s Role in Geopolitical Conflict [[link]](https://blog.chainalysis.com/reports/2022-crypto-crime-report-preview-ransomware/)
+ 최근 6년간 랜섬웨어 피해 금액
- 2021년부터 2022년 1월 현재 랜섬웨어로 인한 지불금은 6억달러 이상으로 확인
![이미지](1)
 
+ 2021년 랜섬웨어 활동 요약
![이미지](2)

+ 2021년 한해동안 상위10개 랜섬웨어 변종 활동추이
![이미지](3)

#### Chinese Hackers Target Taiwan's Financial Trading Sector with Supply Chain Attack [[link]](https://thehackernews.com/2022/02/chinese-hackers-target-taiwans.html?fbclid=IwAR0xVRWN4sFUjPikLWdVsO9R4bnLQ63GgR2FaBsKVD9Ap9are7SP_z-DCcs)
![이미지](4)

#### 2022년에도 계속되는 다크웹의 한국사랑? 랜섬웨어부터 개인정보 판매까지 [[link]](https://www.boannews.com/media/view.asp?idx=104961&fbclid=IwAR1N17qW4AgooEwyj6Zwhc__1WQ-BVD6amf3TC9nzjz3WtsfhRpq0uLj5O4)
- 현대삼호중공업 랜섬웨어 공격 주장부터 명품 구매대행 시크먼트 고객정보 판매 글까지 게재
1. 현대삼호중공업 랜섬웨어 공격
	+ 공격대상 : 현대삼호중공업
	+ 공격기법 : Hive Ransomware
		* 2021년 6월에 처음 등장하여 이중 갈취(민감데이터 유출 및 랜섬웨어 공격) 랜섬웨어 그룹
		* 언어의 동시성 기능을 활용하여 파일을 더 빠르게 암호화하기 위해 Go로 작성
	+ Hive 랜섬웨어 에서 사용하는 파일별 기능 목록(버전별로 상이함)
		* hive.bat : 자가 삭제 등의 삭제 루틴 실행한다.
		* Shaow.bat : 볼륨 섀도우 복사본, 백업 파일 및 시스템 스냅샷 등을 삭제한다.
		* Winlo.exe : 7zG.exe 파일일 드롭한다.
		* 7zG.exe : 7-Zip 압축파일. Winlo_dump 64 SCY.exe 파일일 드롭한다.
		* Winlo_dump_64_SCY.exe : 파일 암호화 및 랜섬노트를 생성한다.
	+ Image Reference : https://twitter.com/S0ufi4n3/status/1495875031804657665
		![이미지](5)
2. 관련기사
	1. 랜섬웨어 공격 현대삼호重 "복구 거의 완료...업무 정상화" (2022.01.18) [[link]](https://news.mt.co.kr/mtview.php?no=2022011809435088301)
	2. 헬스케어 대상으로한 공격 분석 [[link]](https://www.sentinelone.com/labs/hive-attacks-analysis-of-the-human-operated-ransomware-targeting-healthcare/)
	3. Hive Ransomware(Author : Christopher Kim, 2021.08.30) [[link]](https://blogs.infoblox.com/cyber-threat-intelligence/cyber-threat-advisory/hive-ransomware/)
	4. FBI(2021.08.30), Indicators of Compromise Associated with Hive Ransomware [[link]](https://www.ic3.gov/Media/News/2021/210823.pdf)
	![이미지](6)
	5. A Method for Decrypting Data Infected with Hive Ransomware(February 18, 2022) [[link]](https://arxiv.org/pdf/2202.08477.pdf)
	![이미지](7)
 
#### DarkFeed : DeepWeb Intelligence Feed [[link](https://darkfeed.io/ransomwiki/)
- HiveLeaks에서 나오는 내용을 직접 접근하고자 했으나 제대로 정보가 안나옴..ㅠ_ㅠ
- Tor Browser에서 onion주소를 알아내려고 DarkFeed까지는 검색에 성공(회원가입을 시도하고 있으나 @protonmail.com은 거부당해서 다른 메일주소를 찾아야 할듯함)
![이미지](8)
- But, Hive Leaks의 Tor경로를 따라가면 아무런 정보가 없어서 뭐지 싶은 생각 [[link]](http://hiveleakdbtnp76ulyhi52eag6c6tyc3xw7ez7iqy6wc34gd2nekazyd.onion.ly/)
![이미지](9) 
- 검색해본 결과 왠지 시간이 지나면 해당 정보가 보이지 않는듯함…(아래 이미지는 검색결과)
![이미지](10)
- 위에 사이트정보가 잘못됬나 싶다가도 CLOP 랜섬웨어 감염시에 정보유출 페이지 [[link]]((https://santat7kpllt6iyvqbr7q4amdv6dzrh6paatvyrzl7ry3zm72zigf4ad.onion.ly/)의 경우에는 정상적으로 동작해서 그냥 내가 그다음 스텝을 못찾고 있는 듯함…..)
![이미지](11)


# [ Vulnerability ]
---
#### Unpacking CVE-2021-40444: A Deep Technical Analysis of an Office RCE Exploit [[link]](https://www.virustotal.com/gui/file/3bddb2e1a85a9e06b9f9021ad301fdcde33e197225ae1676b8c6d0b416193ecf/)
- 분석 대상(MD5) : 6f194654557e1b52fb0d573a5403e4b1
- 취약점 : CVE-2021-40444
- 공격절차
	1. 피해자(Victim)이 악성Word문서를 열람
	2. Word는 공격자의 HTML페이지를 OLE개체로 로드하고 포함된 JavaScript를 실행
	3. iframe이 생서되고 소멸되지만 ActiveX 스크립팅 표면에 대한 참조는 남아 있음
	4. CAB파일이 해당 파일에 대한 ActiveX컨트롤을 만들어 호출
	5. CAB파일의 서명이 확인되는 동안 포함된 INF파일은 사용자의 Temp디렉토리에 가록
	6. 마지막 INF는 상대경로의 이스케이프를 사용하여 임시 디렉토리에 도달하는 URL프로토콜로 ‘.cpl’확자자를 사용하여 호출
- 참고도구
URLProtocolView : https://www.nirsoft.net/utils/url_protocol_view.html
![이미지](12) 

# [ Forensic ]
---
#### Windows security log quick reference for SOC Analysts
![이미지](13)

#### Leveling Up with osquery for Workloads: Identifying and Contextualizing Windows Logon Failures - Part 1 [[link]](https://carbonblack.vmware.com/blog/leveling-osquery-workloads-identifying-and-contextualizing-windows-logon-failures-part-1?fbclid=IwAR1-Ym6eqHgcUtg4y3S5Cp9kKsuXDWmZ4BA2bZvJpHl5A-jVnnfSWlTbllw&utm_campaign=social-general&utm_content=blog&utm_medium=organic-social&utm_source=twitter&utm_term=none)
+ System Logon Events (Mac/Linux)
	- Mac/Linux에서 로그인 및 로그아웃 기록을 보기 위해서는 ‘last’명령어를 사용
	![이미지](14)
	- osquery에서는 ‘select * from last;’라고 검색가능
		* osquery : OS의 다양한 자원들에 대해 리눅스 CLI가 아닌 RDB에 질의하는 것처럼 쿼리를 날려서 정보를 제공하는 도구
		ㄴ osquery, 어떻게 활용할 것인가? : https://brunch.co.kr/@alden/4
		ㄴ Osquery로 Linux 서버 보안을 모니터링하는 방법 : https://ko.linux-console.net/?p=248
		![이미지](15)
 	- tty을 사용하는 경우 아래 내용에 유의가 필요
		ㄴ tty# : 가상 커미널로 사용자가 터미널과 같은 앱을 열 때 표시
		ㄴ pts/# : 사용자가 네트워크(예: ssh연결)을 통해 로그인 할 때 표시
		ㄴ :# : 사용자가 연결된 디스플레이이며 GUI사용을 표기
	- 해당 블로깅내용에서 중요한 점은 osquery를 통해서 기존의 결과보다 훨씬더 많은 정보 획득이 가능하다는 점
	![이미지](16)
 

#### EvtxECmd [[link]](https://github.com/EricZimmerman/evtx)
- Introducing EvtxECmd!!  : https://binaryforay.blogspot.com/2019/04/introducing-evtxecmd.html
- KAPE와 EvtxECmd를 이용하면 윈도우 이벤트로그 분석을 EventLogExplorer이외에도 유용할 듯

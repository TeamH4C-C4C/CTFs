# 문제 제목 : Mine Over Matter

# 문제

귀하의 SOC에서 네트워크의 한 부분에서 비정상적인 외부 트래픽을 플래그했습니다. 이상 현상 중에 라우터에서 로그를 캡처한 후, 네트워크 분석가인 귀하에게 전달했습니다.

이 혼란 속 어딘가에 두 개의 손상된 호스트가 비밀리에 암호화폐를 채굴하고 리소스를 소모하고 있습니다. 트래픽을 분석하고, 채굴기를 실행하는 두 개의 불량 IP 주소를 식별하여 네트워크가 암호화폐 농장이 되기 전에 사고 대응팀에 보고하십시오.

번역기야 고마워..

# 풀이 
이것도 grep으로 풀면 됐는데, 아웃바운드로 나가는거 잡아서 풀었습니다. 근데 솔브 코드 백업을 깜박하고 노트북을 포맷 해버려서..
공식 라업의 솔브코드를 첨부하겠습니다.

```py
import subprocess, re

inputFile = "logs.txt" 
uniqueIPsDest = set()
uniqueIPsSrc = set()
ipDomainMap = {}

with open(inputFile, 'r') as file:
    for line in file:
        fields = line.strip().split(',')
        if len(fields) >= 20:
            destIP = fields[19]
            uniqueIPsDest.add(destIP)

for ip in sorted(uniqueIPsDest):
    try:
        result = subprocess.run(["nslookup", ip], capture_output=True, text=True, check=True)
        if 'mine' in result.stdout.strip():
            match = re.search(r'name\s*=\s*(.+)\.', result.stdout)
            domain = match.group(1)
            ipDomainMap[ip] = domain
            print(f"{ip} -> {domain}")
    except subprocess.CalledProcessError as e:
        pass

with open(inputFile, 'r') as file:
    for line in file:
        fields = line.strip().split(',')
        if len(fields) >= 20:
            srcIP = fields[19]
            for ip, domain in ipDomainMap.items():
                if ip == srcIP:
                    uniqueIPsSrc.add(fields[18])

print("Source Addresses For Miners")
for ip in uniqueIPsSrc:
    print(ip)
```

flag:`byuctf{172.16.0.10,172.16.0.5}`
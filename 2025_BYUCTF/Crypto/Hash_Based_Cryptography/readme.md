# Hash Based Cryptography

한 블록의 크기는 20 바이트(sha1 output 크기).

입력이 20의 배수로 들어올 때 추가적인 20 바이트 더미를 추가 안 함.

복호화 오라클도 있어서 otp 복구 가능함.

## 문제 코드 분석

### OTP gen_otp

같은 (key, message) 쌍을 input으로 넣으면 같은 otp가 나와서 One Time Password의 요건을 충족시키지 못한다.

그래서 otp를 복구하면 아래의 암복호화가 그 순간부터 무력화된다.

### 암호화 encrypt

input : key, pt
output : ct

1. pt를 패딩해서 pt' 생성
2. gen_otp(key, pt')로 otp 생성
3. pt' ^ otp = ct 리턴

### 복호화 decrypt

input : key, ct
output : pt or "Error decrypting"

1. ct를 패딩(?)해서 ct' 생성
2. gen_otp(key, ct')로 otp 생성
3. ct ^ otp = pt 생성
4. unpad 과정에서 에러 발생 시 "Error decrypting" 리턴
5. 에러가 없었다면 pt 리턴

### 패딩 pad

패딩이 어딘가 이상하다는걸 가장 먼저 알아봤어야 한다.

pkcs #7 패딩을 하는 것처럼 보이지만 20의 배수인 케이스를 확인해보면 아무것도 추가하지 않는 것을 알 수 있다.

## 풀이 도출 과정

다음 두 특성을 조합해서 otp를 복구할 수 있다.

1. 복호화 및 패딩 오라클
2. 메시지의 길이가 20의 배수이면 패딩 미수행

이를 통해 내가 제시한 암호문이 잘 패딩이 되어있는지 알 수 있다 => otp를 브루트포스로 xor 해나가며 알아낼 수 있다.

## 익스 코드 설명

### extract_otp(20,r)과 extract_otp(40, r)

`otp = sha1(iv) | sha1(sha1(iv)) | sha1(sha1(sha1(iv))) | ...`

otp는 블록 개수만큼 재귀적으로 sha1 인코딩해서 생성하는데 flag는 블록이 2개라서 한 번에 알아내려고 하면 패딩이 20바이트 단위이기 때문에 불가능하다. 그래서 extract_otp를 20바이트 페이로드로 앞 부분, 40바이트 페이로드로 뒷 부분을 추출한다.

### brute==256에서 i -= 1

DFS로 가능한 otp 조합을 찾아내자는 논리.

### try-except

"Padding error" 이후 server에서 ValueError를 raise하기 때문에 통신이 끊겨서 새로운 통신을 열어주기 위한 코드.
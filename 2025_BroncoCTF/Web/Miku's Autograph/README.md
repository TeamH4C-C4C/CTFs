# Miku's Autograph

## Target Difficulty: Medium

## Description
I am so proud of the fact that I have Miku's autograph. Ha! You don't!

https://miku.web.broncoctf.xyz

## How to solve
`/get_token`을 통해 Token 값을 받을 수 있는데 확인해보면 JWT형식이다. jwt.io에 Token 값을 넣고 확인해보면 HS256을 사용했고 sub값을 통해 사용자 인증을 하는 것을 알 수 있다.
이때 HS256을 none으로 변경하고 sub를 `miku_admin` 으로 변경한뒤 Token값을 생성한 다음 `/get_token`에서 발급되는 Token 값을 해당 값으로 변경하면 Flag 획득 가능

## Flag
bronco{miku_miku_beaaaaaaaaaaaaaaaaaam!}
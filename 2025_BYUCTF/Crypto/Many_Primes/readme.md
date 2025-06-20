# Many Primes

n이 (10bits ~ 16bits prime) ** (2 ~ 5)의 곱으로 이루어져 있으므로 간단하게 인수분해가 된다.

그러면 phi_N을 모든 소인수 $p^k$에 대해 $\prod (p-1)p^{k-1}$을 구한 다음, $ed\equiv 1 \pmod{\phi(N)}$인 $d$를 구해서 복호화하면 된다.
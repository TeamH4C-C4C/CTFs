````import numpy as np
import matplotlib.pyplot as plt
from scipy.signal import spectrogram

# IQ 데이터 파일 경로 (예시로 raw 파일 사용)
file_path = "dotdotdot.iq"

# IQ 데이터 읽기 (16비트 signed integer 형식)
iq_data = np.fromfile(file_path, dtype=np.int16)

# I, Q 데이터 분리
I_data = iq_data[::2]  # 짝수 인덱스: I
Q_data = iq_data[1::2]  # 홀수 인덱스: Q

# I + jQ 복소수 데이터로 결합
complex_data = I_data + 1j * Q_data

# 샘플링 주파수 설정 (예시로 1MHz 가정)
sampling_rate = 1e6

# 스펙트로그램 계산
frequencies, times, Sxx = spectrogram(complex_data, fs=sampling_rate)

# 스펙트로그램 그리기
plt.figure(figsize=(10, 6))
plt.pcolormesh(times, frequencies, 10 * np.log10(Sxx), shading='auto')
plt.ylabel('Frequency [Hz]')
plt.xlabel('Time [sec]')
plt.title('Spectrogram')
plt.colorbar(label='Power [dB]')
plt.show()
````
위의 코드를 통해 iq 파일을 스팩토그램으로 변환하면 모스코드가 나온다.
해당 모스코드를 변환하면 플래그이다.


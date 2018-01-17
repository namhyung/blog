---
layout: post
category: kernel
title: Spectre 취약점에 관하여 (1)
summary: Spectre (variant 1) 취약점과 이를 회피하기 위한 패치 소개
tag: kernel security
---

# Spectre 취약점
[지난 글](meltdown-and-page-table-isolation)에서 Meltdown 취약점에 대해서 다루어보았는데
이번에는 함께 공개된 Spectre 취약점에 대해서도 살펴보겠습니다.

앞서 말한 듯이 Spectre 취약점은 두 가지 variant가 존재합니다.
그 중 variant 1 (array-bounds-check)는 Meltdown (variant 3)과도
공통점이 많이 있으니 지난 글의 내용을 참고하시기 바랍니다.

## variant 1: bounds check bypass
앞서 살펴본 variant 3 (Meltdown) 취약점과 마찬가지로
variant 1의 경우 범위를 벗어난 배열 접근이 문제의 핵심입니다.
다만 variant 1의 경우는 커널 내의 데이터를 접근하기 위해
커널 내의 코드를 직접 이용해야 하는 차이점이 있습니다.

이를 위해 사용할 수 있는 방법은 최신 커널에서 제공하는 eBPF 기능입니다.
간단히 말해 eBPF (extended Berkeley Packet Filter)는
커널 내에서 실행되는 작은 가상 머신으로써 사용자가 작성한 코드를
(제한된 환경 하에서) 직접 실행하여 특정 작업의 성능을 높이고자 하는 것입니다.
추가로 eBPF JIT (Just In Compile) 기능을 이용하면 eBPF 코드가
machine instruction으로 컴파일되어 실행됩니다.

이름에서 알 수 있듯이 eBPF는 원래 소켓으로 오가는 데이터를 filtering하기 위해
사용하였으나 점차 그 사용처가 늘어나서 다른 분야에서도 사용하고 있습니다.
eBPF 코드는 커널 내에서 실행되기 때문에 보안 위협을 낮추기 위해
커널에 load될 때 verifier가 코드를 분석한 후 위험하다고 판단하면 실행을 거부합니다.
하지만 variant 1을 위해 사용하는 코드는 verifier가 위험을 예측할 수 없는 정상적인 코드이고,
더욱이 socket filter 기능으로는 root가 아닌 일반 사용자 권한으로도 load할 수 있습니다.

구글의 Zero 프로젝트 블로그에 나온 공격 방법은 대략 다음과 같습니다.
먼저 eBPF에서 사용자 공간의 특정 메모리에 접근하기 위한 offset을 알아냅니다.
eBPF에서 배열은 map이라는 형태로 접근 가능한데
여기서는 일종의 function pointer를 저장하는 prog_map을 사용하였습니다.
prog_map에 접근할 때는 `bpf_tail_call()` 함수를 이용합니다.

이 때도 마찬가지로 speculative execution에 의한 cache update를 고려하여
이미 알고있는 두 지점의 load (data read) 시간차를 통해 offset을 얻을 수 있습니다.
다만 무식한 방법으로 모든 offset 값을 시도하는 것은 너무 느리기 때문에
(물리 메모리 페이지가 공유되는) 가상 메모리의 특성을 활용하는 기법을 사용하였습니다.

이렇게 알아낸 offset이 있다면 이제 또 하나의 eBPF 코드를 이용하여
커널 내의 데이터를 speculation을 통해 접근하고 (victime_map)
이 정보를 앞서 알아낸 prog_map + offset을 통해 사용자 공간으로 넘길 수 있습니다.

```c
secret_data = bpf_map_read(victim_map, secret_data_offset);
prog_idx = ((secret_data & data_mask) << 7) + prog_map_offset;
bpf_tail_call(prog_map, prog_idx);
```

사용자가 `secret_data_offset` 및 `data_mask` 값 등을 잘 조정한다면
prog_map을 통해 접근한 사용자 메모리에서 커널 데이터를 읽어내는 것이 가능합니다.

이와 비슷하게 Java-Script JIT 엔진을 활용하여 비슷한 코드를 만들어 낼 수 있다면
Java-Script 코드 내에서 브라우저 내부의 사용자 정보를 알아낼 수 있는 공격이 가능할 것 입니다.

## 대책
안타깝게도 이 문제를 겪고 있는 모든 Intel, AMD, ARM cpu의 경우
이를 근본적으로 해결할 수 있는 방법은 없는 듯 합니다.
또한 문제가 될 수 있는 모든 프로그램의 해당 코드 지점마다
방어 코드를 직접 넣어야하기 때문에 이를 놓치거나 새로 발생할 여지가 다분히 있습니다.

하지만 커널 내의 (현재 알고 있는) 문제가 될 수 있는 코드 (중의 일부)를
방어하기 위한 패치가 작업 중입니다.

우선적으로 eBPF에서는 배열(map) 접근 시 index를 직접 접근하지 않고
배열의 크기를 넘어서지 않도록 보장하는 mask를 적용하는 패치가 이미 merge 되었습니다.
간단히 말하면 배열 접근 시 `array[index & mask]` 의 형태로 코드를 변경하는 것입니다.

일반 커널 코드에서도 배열 접근 시 사용자에 의해 index가 설정될 수 있는 부분에는
비슷한 방식의 코드를 생성하도록 `array_ptr` 매크로를 추가하는 패치가 논의 중입니다.
배열 접근 시 array_ptr 매크로를 사용하면 비정상적인 index에 대해서는 NULL을 리턴합니다.

mask 값은 배열의 크기가 2의 지수승인 경우는 간단히 '크기 - 1' 값을 사용하면 될테지만
일반적인 경우는 그럴 수 없기 때문에 다음과 같은 형태로 계산합니다.

```c
#define array_ptr_mask(index, size)
({
   ~(long)(index | size - 1 - index) >> (BITS_PER_LONG - 1);
})

#define array_ptr(array, index, size)
({
   mask = array_ptr_mask(index, size);
   ptr = array + (index & mask);
   ptr & mask;
})
```

여기서 mask는 index 값에 따라 0 혹은 -1 (= `0xffff...`) 중의 하나가 되는데
보다 직관적인 형태의 코드는 다음과 같을 것입니다.

```c
#define array_ptr_mask(index, size)
({
   if (index >= size)
      mask = 0;
   else
      mask = -1;
   mask;
})
```

하지만 이는 또다시 speculative execution에 영향을 받기 때문에
branch 없이 mask를 계산하는 것이 중요합니다.
따라서 위의 복잡한 mask 계산은 다음과 같은 세 단계로 나누어 생각해 볼 수 있습니다.

```c
#define array_ptr_mask(index, size)
({
   tmp1 = index | size - 1 - index;
   tmp2 = ~tmp1;
   (long)tmp2 >> (BITS_PER_LONG - 1);
})
```

먼저 tmp1은 index 와 size 값에 따라 양수 혹은 음수가 됩니다.
index가 양수이고 size 보다 작은 값(= 정상적인 값)이라면 tmp1은 양수입니다.
그렇지 않다면 tmp1의 값은 음수가 됩니다. tmp2는 단순히 tmp1의 비트를 뒤집은 형태입니다.
이제 tmp2를 (signed) long 타입으로 변경하여 (arithmetic) right shift 합니다.
`BITS_PER_LONG`은 시스템에 따라 64 혹은 32 라는 값을 가지므로
결국 tmp2의 최상위 비트가 mask의 전체 비트에 복사됩니다.

이렇게 mask를 이용하는 방식 외에도 cpu architecture에 제공하는
특별한 방법을 통해 speculation을 방지하는 'ifence' 라는 패치도 존재하는데
현재까지는 mask 방식이 더 힘을 받고 있습니다.

아직 variant 2는 시작도 못했는데 벌써 글이 꽤 길어졌네요.
일단 여기서 마무리하고 다음 기회에 다시 variant 2에 대해 다루어 봐야겠습니다.


## 참고
* [Google Project Zero blog](https://googleprojectzero.blogspot.kr/2018/01/reading-privileged-memory-with-side.html)
* [LWN article](https://lwn.net/Articles/744287/)
* [Kernel patch](https://git.kernel.org/pub/scm/linux/kernel/git/djbw/linux.git/log/?h=nospec-v3)


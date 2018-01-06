---
layout: post
category: kernel
title: Meltdown 취약점에 관하여
summary: Meltdown 취약점과 이를 회피하기 위한 KPTI 패치 소개
tag: kernel security
---

# CPU 버그를 이용한 취약점 발표
연초에 발표된 중대한 CPU 취약점으로 인해 온통 시끄럽길래 저도 한 번 들여다보았습니다.
Google Project Zero 블로그에 아주 상세하게 설명되어 있는 내용이긴 하지만
이해하기에 쉽지않은 부분이 있어서 정리해 보려고 합니다.

이 취약점은 CPU의 성능을 높이기 위한 기법들에 의해 발생되는 side-effect를
이용하는 것으로 구체적으로 branch prediction과 speculative execution이라는
기법에 해당합니다.

이러한 취약점은 3가지 형태의 변종(variant)이 존재하는데 각각의 다음과 같습니다.

* variant 1: bounds check bypass
* variant 2: branch target injection
* variant 3: rogue data cache load

이 중 첫번째와 두번째 형태를 Spectre, 세번째는 Meltdown이라고 부릅니다.
여기서는 이 세 가지 중에서 그나마 가장 이해하기 쉬운(?) Meltdown에 대해서 살펴보겠습니다.

## Meltdown 취약점
Meltdown 취약점이 문제가 될 수 있는 코드를 먼저 살펴보겠습니다.
우선 다음과 같은 자료구조가 있다고 가정하겠습니다.

```c
struct array {
   unsigned long len;
   unsigned char data[];
};
```

C언어의 flexible array 기능을 이용하여 자료구조의 크기를 동적으로 결정하는 기법으로
data 필드에 접근하기 전에 먼저 index가 len 보다 작은지 검사하는 코드가 필요합니다.

```c
struct array *a1;
unsigned long index;

...

if (index < a1->len) {
   unsigned char val = a1->data[index];
   ...
}
```

어디선가 이러한 코드가 자주 실행되고, index는 어떠한 형태로든 사용자가 조정 가능한
상황을 가정해 보겠습니다. 일반적으로 index 값은 len 보다 작을테니 if 문의 조건은
true를 반환하고 내부의 코드가 실행될 것입니다.

그러나 어느 순간 (악의적인) 사용자가 갑자기 index를 잘못된 (엄청 큰) 값으로 설정하면
어떻게 될까요? 당연히 if 문은 실패할 것이고 내부의 코드는 실행되지 않을 것입니다.

그렇지만 여기서 바로 문제가 발생할 수 있습니다. CPU는 메모리에 비해 실행 속도가 무척
빠르기 때문에 데이터 사용 시 메모리에 접근하는 것을 최대한 피하고
자주 사용하는 데이터를 가능하면 캐시에 저장하여 사용하게 됩니다.

만약 a1->len 값이 캐시에 없었고, index 값은 캐시에 있었다면 어떨까요?
if의 조건문을 검사하기 위해서는 두 값이 모두 필요하기 때문에
CPU는 조건문을 실행할 수 없고 따라서 블록 내부의 코드가 실행될지 아닐지 알 수 없습니다.

이 때 바로 branch prediction을 이용하게 되는데, (그 내부는 복잡하겠지만)
간단히 말해 이전에 이 코드가 true를 리턴했다면
다음에도 (아마) true를 리턴할 것이라고 가정하는 것입니다.

그러면 CPU는 잘못된 index에 대해서 내부 코드를 실행하게 될 위험이 있습니다!

하지만 이런 위험천만한 작업을 아무 대책없이 실행해 버리지는 않겠죠.
CPU는 이와 같은 상황을 speculative execution이라고 인식하고
이 상황에서 실행되는 코드의 결과를 임시 공간에 저장하고 있다가
실제 if문의 조건문이 false라고 밝혀지는 순간 모두 버리게 됩니다.
따라서 위와 같은 코드에서 잘못된 index를 사용한 val 값을 사용자가 볼 수 없습니다.

하지만 여기서 끝난다면 지금 이 글을 쓰고있을 이유가 없겠죠?
당연히(?) 이를 회피하는 문제가 바로 이 Meltdown 취약점에 해당합니다.

앞서 speculative execution의 결과는 모두 버려진다고 말씀드렸나요?
하지만 이 결과가 간접적으로 영향을 주는 부분이 하나 있으니
그것은 바로 앞서 얘기한 '캐시'입니다.

만약 index가 data를 벗어나 다른 영역에 속한 메모리의 주소를 가리키고 있었다면
이 메모리의 내용이 캐시에 저장될 것입니다. 하지만 이 사실 만으로는 그 영역에
직접 접근할 권한이 없는 경우 아무런 소용이 없습니다.
그렇다면 다음과 같은 코드는 어떨까요?

```c
...

if (index < a1->len) {
   unsigned char val = a1->data[index];

   unsigned long idx2 = (val & 1) * 256;
   if (idx2 < a2->len) {
      unsigned char val2 = a2->data[idx2];
      ...
   }
   ...
}
```

아까와 동일한 코드에서 a2 자료 구조가 추가되었습니다.
설명의 편의를 위해 a2의 크기는 512 정도로 할당되었고
data 배열의 모든 자료는 캐시에 저장되지 않았다고 가정하겠습니다.

이제 위의 코드에서 주의할 부분은 idx2를 계산하는 부분인데
a1을 통해서 읽은 값의 최하위 비트를 이용해서 a2에 접근할 위치를
결정합니다. 결국은 idx2는 0 혹은 256 중의 하나의 값을 가질 것입니다.

그 다음은 동일하게 a2의 data에 접근하는 코드인데,
제 생각에는 if 문은 생략해도 될 것 같습니다만 일단 원문과 같이 남겨두겠습니다.
아무튼 이러한 코드가 speculative execution으로 실행되면
(index에 해당하는) val의 값 자체는 알 수 없더라도
최하위 비트의 값에 따라 idx2 값에 영향을 주게됩니다.
다시 (speculative execution에 따라) a2->data에 접근하면
val2의 값 자체는 사라지더라도
a2->data[0] 혹은 a2->data[256] 중의 하나는 캐시에 저장되게 됩니다.

그렇게 되면 나중에 (if 문 바깥에서) a2->data를 읽을 때
a2->data[0]과 a2->data[256]을 모두 읽어서 그 시간을 비교하면
둘 중의 어느 것이 캐시에 저장되었었는지 알아낼 수 있고
이를 통해 간접적으로 val 값(의 한 비트)을 알아낼 수 있습니다.
이를 반복하면 모든 데이터를 알아내는 것도 가능할 것입니다!!

사실 여기까지는 Spectre (variant 1) 취약점과 동일한 문제입니다.
하지만 Meltdown이 더 심각한 것은 바로 page table의 접근 권한 검사가
사실 상 이루어지지 않는다는 것에 있습니다.

## Kernel Page Table Isolation
리눅스에서 동작하는 프로세스는 자신의 주소 공간을
커널 영역과 사용자 영역으로 나누어 관리합니다.
간단히 말해 (64비트 기준) 포인터 값의 최상위 바이트가 0x00이면
이는 사용자 영역의 주소이고 0xff이면 커널 영역의 주소입니다.

사용자 코드는 포인터 값을 임의로 설정할 수 있지만
커널 영역의 주소 혹은 매핑되지 않은 사용자 영역의 주소를 접근하는 경우
MMU (hardware)가 이를 인식하여 page fault를 발생시키고
커널은 주어진 정보를 활용하여 적절한 동작을 취하게 됩니다.

하지만 최근의 CPU들은 성능 상의 이유로 speculative execution 시에
page fault를 발생시키는지에 대한 검사를 수행하지 않는 것으로 보입니다.
따라서 일반적인 상황에서 a1->data + index가 만약 커널 영역에 해당하는
경우라면 page fault가 발생하여 프로세스가 종료될 테지만 (segmentation fault)
speculative execution 동안에는 이 값이 val에 저장되게 됩니다.

AMD의 CPU들은 이러한 문제를 가지고 있지 않지만, Intel과 ARM의 CPU들은
(대부분) 같은 문제를 가지고 있습니다.

이를 회피하기 위한 방법으로 애초에 프로세스의 주소 공간 내에서
커널 영역을 없애버리는 것이 바로 Kernel Page Table Isolation (KPTI) 패치의
기본 아이디어 입니다. 이렇게 되면 사용자가 어떠한 주소를 이용한다고 하더라도
커널 영역에 접근할 수가 없으므로 Meltdown 취약점으로부터 커널 데이터를
보호할 수 있습니다. 사실 커널 영역에는 모든 프로세스의 데이터가 다 들어있으므로
커널 뿐 만이 아니라 시스템 전체의 데이터에 해당합니다.

원래 커널 영역이 사용자 영역과 같이 한 주소 공간 내에 들어있게 된 것은
성능을 높이기 위한 조치였습니다. 프로세스가 system call을 호출하는 경우
사용자 프로그램 대신 커널 코드가 실행되고 이를 모두 마친 후에 다시
사용자 프로그램이 실행됩니다. 이렇게 system call을 호출할 때 마다
코드를 실행하기 위한 context의 전환이 발생하는데 이 때마다 주소 공간이
변경된다면 메모리 주소 변환을 위한 TLB 데이터도 사용할 수 없게 되어
코드 실행 및 메모리 접근 성능이 나빠지게 됩니다. 프로그램이 얼마나 자주
system call을 호출하는지에 따라 달라지겠지만 대략 5% 에서 최악의 경우(?)
30% 정도까지 성능 저하가 일어나는 것을 확인했다고 합니다.

사안의 중요성에 따라 KPTI 패치는 (늦은 시기에도 불구하고) 4.15 커널에 포함되었고
Spectre 취약점에 대한 패치들은 아직 개발이 이루어지고 있습니다.

벌써 (의도하지 않게 ㅜ.ㅜ) 이 글도 꽤 길어졌는데
가능하면 다음 번에는 Spectre 취약점에 대해서도 다루어보도록 하겠습니다.

## 참고
* [Google Project Zero blog](https://googleprojectzero.blogspot.kr/2018/01/reading-privileged-memory-with-side.html)
* [LWN article](https://lwn.net/Articles/742702/)
* [Meltdown and Spectre homepage](https://spectreattack.com/)


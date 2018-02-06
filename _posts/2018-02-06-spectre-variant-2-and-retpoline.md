---
layout: post
category: kernel
title: Spectre 취약점에 관하여 (2)
summary: Spectre (variant 2) 취약점과 이를 회피하기 위한 retpoline 기능 소개
tag: kernel security
---

# Spectre 취약점
[지난 글](spectre-variant-1)에 이어서 Spectre 취약점 (variant 2)에 대해 살펴보겠습니다.

Spectre variant 2의 경우 앞서 보았던 것들과 성격이 조금 다르지만
실질적인 공격을 위해서는 variant 1의 취약점을 함께 이용하게 됩니다.

## variant 2: branch target injection
주어진 코드를 실행하여 정보를 얻어내는 variant 1 및 3와 달리
이 취약점은 branch predictor를 공격하여 (잠시동안) 의도하지 않은 코드를 실행하도록 만든다는 것이 특징입니다.

이 때 indirect branch를 이용하는데, branch target이 명확히 정의된 (static) direct branch와 달리
indirect branch는 특정 변수의 값을 읽어 target을 runtime에 결정하므로
branch predictor가 예측하는 target address를 임의로 변경할 수 있다면
speculative execution을 통해 공격자가 원하는 코드를 실행할 수 있을 것입니다.

또한 branch prediction state는 cpu 단위로 유지되기 때문에
자신의 (process) address space를 벗어나서 다른 process의 코드 흐름을 변경할 수 있는데
따라서 kernel을 포함하여 web browser 및 hypervisor 등의 주요 코드에 대한 공격이 가능합니다.

하지만 실질적으로는 branch predictor 내부의 동작을 상세히 이해하고
이와 동일한 조건을 만들어낼 수 있어야 하기 때문에 상당히 까다로운 공격 방식이 될 것입니다.

구글 Zero 프로젝트 블로그에 branch predictor의 내부 동작 방식을
reverse engineering을 통해 알아내는 과정이 설명되어 있으니
관심있는 분들은 참고하시면 좋을 것 같습니다.

이를 통해서 다음과 같이 공격을 수행하는 시나리오가 존재합니다.

KVM을 이용하는 cloud computing 환경에서 guest machine에서
hypercall을 통해 host machine에게 서비스를 요청하는 경우
host가 이를 처리하고 guest로 실행을 넘기게 됩니다.

이 때 indirect call이 호출되는데 KVM generic layer에서
각 cpu 별로 (Intel 혹은 AMD) 구현된 가상화 기능에 따라 다른 동작을 수행하기 때문입니다.
따라서 guest는 정교한 방식으로 작성된 코드를 통해 hypercall 직후에 
branch history state를 dump하여 host 내의 indirect call이 발생한 당시의
branch predictor의 상태를 알아낼 수 있습니다.

그 다음에는 guest 내에서 이와 동일한 상태를 만든 뒤
공격자가 원하는 위치로 branch를 수행하는 코드를 실행하여
branch predictor에게 해당 정보를 기억하도록 만듭니다.
이 때 중요한 것은 guest 내의 코드와 host의 코드가 같을 필요가 없다는 점입니다.
중요한 것은 branch 당시의 (virtual) address 일텐데
다행히도(?) branch predictor는 branch 당시의 전체 (source + destination) address를
기억하는 것이 아니라 그 중의 일부 bit 만을 기억하고 있으므로 공격이 좀 더 쉬워집니다.

여기까지의 과정을 마치고 나면 공격을 위한 준비가 마쳐진 상태이고
어떻게 보면 variant 1과 동일한 상황이 구성되었다고 볼 수 있습니다.
실제적으로 정보를 빼서 guest 쪽으로 넘기는 과정은 variant 1과 유사합니다.

공격 코드는 host 상에서 실행되기 때문에 모든 메모리 영역에 접근할 수 있습니다.
이제 guest 쪽에 볼 수 있는 페이지 하나를 찾아서 정보를 넘겨주기만 하면 됩니다.
실제로 host 내의 gadget을 찾아서 실행할 수도 있을테지만 eBPF를 이용하면 좀더 간단합니다.

## 대책
variant 2의 공격 대상이 indirect branch이기 때문에, 코드 상에서 indirect branch를
완전히(?) 제거하기 위한 retpoline (return trampoline) 패치가 개발되었습니다.

최신의 gcc 7.3 버전을 사용하면 x86_64 아키텍처에서 `-mindirect-branch=thunk` 옵션을 통해
retpoline을 적용할 수 있습니다.

indirect.c:
```c
struct ops {
  int (*bar)(int a, int b);
};

int foo(struct ops *op)
{
  return op->bar(1, 2);
}
```

위의 코드에서 ops 구조체의 bar를 함수 포인터를 통해 호출하면 indirect call을 실행하는
코드가 생성됩니다. `call` 명령 부분을 주의해서 보기 바랍니다.

```
$ gcc -S -o indirect-keep.s -fno-asynchronous-unwind-tables indirect.c

$ cat indirect-keep.s
	...
foo:
	pushq	%rbp
	movq	%rsp, %rbp
	subq	$16, %rsp
	movq	%rdi, -8(%rbp)
	movq	-8(%rbp), %rax
	movq	(%rax), %rax
	movl	$2, %esi
	movl	$1, %edi
	call	*%rax
	leave
	ret
	...
```

이제 gcc에 `-mindirect-branch=thunk` 옵션을 추가하면 해당 코드가 다음과 같이 바뀝니다.

```
$ diff -U1 indirect-{keep,thunk}.s
--- indirect-keep.s	2018-02-06 12:24:44.302941667 +0900
+++ indirect-thunk.s	2018-02-06 12:37:50.799399143 +0900
@@ -18,3 +18,3 @@
 	movl	$1, %edi
-	call	*%rax
+	call	__x86_indirect_thunk_rax
 	leave

```

`__x86_indirect_thunk_rax` 함수는 rax 레지스터의 값을 이용하여
indirect call과 같은 동작을 수행하는 retpoline 코드를 아래와 같이 생성합니다.

```
__x86_indirect_thunk_rax:
	call	.LIND1
.LIND0:
	pause
	lfence
	jmp	.LIND0
.LIND1:
	mov	%rax, (%rsp)
	ret
```

이제 하나의 indirect call이 두 개의 direct call로 변경되었습니다.
또한 speculative execution의 경우 .LIND0 부분에서 처리하고 있습니다.
이제 원래의 주소를 스택에 옮긴 뒤 `ret` 명령을 실행하여 호출합니다.

이렇게 retpoline을 이용하면 variant 2로 인한 공격을 막을 수 있겠지만
문제는 이를 지원하는 컴파일러가 최근에야 나왔기 때문에 확산에 시간이 필요하다는 점과
오직 x86_64 만을 지원하기 때문에 다른 arch들은 사용할 수 없다는 점입니다.

각 cpu 제조사들은 이와 별도로 hardware 적으로 branch predictor의 기능을 제한할 수 있는
방법을 제공하고 있기 때문에 필요에 따라 이를 사용해야 할 경우가 있습니다.
따라서 커널에 이러한 패치들을 추가하기 위한 논의와 작업들이 진행되고 있습니다.

## 참고
[Google Project Zero Blog](https://googleprojectzero.blogspot.kr/2018/01/reading-privileged-memory-with-side.html)
https://lwn.net/Articles/743265/
[Google: retpoline](https://support.google.com/faqs/answer/7625886)


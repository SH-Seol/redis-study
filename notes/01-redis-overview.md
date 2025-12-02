# 1. Redis Overview

---
### 1.1 Redis란?
Redis란 무엇일까요? 살바토레 산필리포(이하 antirez)가 만든 인메모리 db입니다.
Remote Dictionary Server의 약자로 key-value 데이터 구조 저장소입니다. 캐싱, 세션 관리, 실시간 데이터 등 다양한 분야에서 사용됩니다.

일반적으로 NoSQL로 구분이 되지만 RDB 개념으로 설계가 가능하고 8버전에서는 rdb 테이블을 도입하는 시도도 존재합니다.

### 1.2 왜 빠를까?
Redis는 in-memory db, 즉 캐시를 사용합니다. 
그래서 기존의 SQL, NoSQL과 같이 hdd, ssd를 사용하는 것보다 더 빠릅니다.
후술하겠지만 hdd, ssd에 저장된 내용들을 가져올 수도 있지만 메인으로 사용하는 것은 캐시이니까요.

### 1.3 왜 만들어졌을까?
Antirez가 과거에 mysql로 작업을 하다가 너무 느리다고 더 빠른 db를 만들고 싶다는 생각을 가지고 만들어진 것이 redis입니다.

### 1.4 주요 특징

1. [싱글 스레드 기반 아키텍처](#1-싱글-스레드-기반-아키텍처)
2. [영속성 지원](#2-영속성-지원)
3. [다양한 자료구조 지원](#3-다양한-자료구조-지원)
4. [TTL](#4-ttl)
5. [I/O 멀티플렉싱](#5-io-멀티플렉싱)
6. [Replication / Cluster 기반 고가용성](#6-replication--cluster-기반-고가용성-지원)
7. [Pub/Sub + Stream 제공](#7-pub--sub--stream-제공)
8. [다양한 Eviction 정책 지원](#8-다양한-eviction-정책-지원)
9. [Memcached와 차이점](#9-memcached와-차이점)

#### 1. 싱글 스레드 기반 아키텍처
Redis는 왜 싱글스레드로 설계를 했을까요?

Antirez는 atomic primitives를 제공하여 개발자가 lock-free한 상태로 개발하기를 바랬습니다.
멀티 스레드에서 자주 있는 데드락, 레이스 컨디션, 락 경쟁으로 인한 latency spike같은 문제를 피하기 위해서입니다.

그렇지만 멀티스레드보다 느리지 않습니다. 이유는 다음과 같습니다.

- 모든 연산이 in-memory라 CPU 연산만 한다
- event loop 기반에다가 I/O 멀티플렉싱을 사용한다.
- 하나의 command 처리 비용이 매우 작다.

다만 Redis 6부터 read/write에서 멀티스레드를 지원합니다.
Socket read/write 작업에 소요되는 시간을 I/O thread를 통해 위임하여 redis 프로세스 전체가 데이터 조작, 저장, 조회 등에 더 많은 CPU cycle을 사용할 수 있습니다. 

사실 Redis는 6버전 이전에도 백그라운드 I/O를 지원했지만 이건 AOF rewrite, 비동기 삭제 등에서만 지원했습니다.
6버전에서는 클라이언트 소켓 read/write 처리를 위한 I/O thread 도입입니다.

관련 내용은 아래 링크에 있습니다.

https://redis.io/blog/diving-into-redis-6/?utm_source=chatgpt.com

#### 2. 영속성 지원
Redis는 인메모리 데이터를 주기적으로 파일에 저장하는데, Redis 프로세스가 장애로 인해 종료되더라도 해당 파일을 읽어서 이전의 상태로 동일하게 복구할 수 있도록 합니다.
2가지 방식을 지원합니다.
1. snapshot(RDB)
    - snapshot방식은 순간적으로 메모리에 있는 내용을 fork()하여 Disk에 옮겨 담는 방식입니다.
    - 특정 시점의 메모리에 있는 데이터를 바이너리 파일로 저장합니다.
    - AOF 파일보다 사이즈가 작아서 로딩 속도가 AOF보다 빠릅니다.
    - 다만 snapshot을 추출하는데 시간이 오래 걸리고 도중에 서버가 꺼지면 이후 모든 데이터가 사라지는 단점이 있습니다.
    - fork() 방식을 사용하기에 메모리를 2배 가량 사용하기에 이에 조심해야 합니다.
2. AOF(Append-Only File)
   - aof 방식은 redis의 모든 write/update 연산 자체를 모두 log에 기록합니다. 조회를 제외한 입력, 수정, 삭제 명령이 실행될 때마다 기록됩니다.
   - 서버가 재시작될 때 write/update 연산을 재 실행하는 형태인데, 여러번 처리된 데이터는 마지막 처리만 진행을 합니다.
   - operation이 진행될 때마다 매번 기록하기에 rdb와 달리 현재 시점까지의 로그를 기록하고 기본적으로 non-blocking으로 동작합니다.
   - 다만 log 파일에 연산이 남아 log 데이터 양이 매우 크고, 복구 시 연산을 다시 실행하기에 재시작 속도가 느린 단점이 있습니다.

#### 3. 다양한 자료구조 지원
Redis는 다양한 자료구조를 지원합니다. 
초기버전에는 String, List, Set 총 3개만 지원했습니다만, 현재는 여기에 SortedSet, Hash, Bitmap, HyperLogLog, Stream을 추가로 지원합니다.

#### 4. TTL
Redis에는 TTL(Time-To-Live)가 존재합니다. 
제한된 메모리 안에 오래된 데이터가 그대로 남는 것을 방지하기 위해서,
또 데이터가 갱신되면 캐시가 낡은 데이터를 계속 갖지 않기 위해 만들어졌습니다.

키 만료 방식은 두가지가 있습니다.
1. Lazy Expiration - 클라이언트가 키에 접근했을 때 삭제
2. Active Expiration - redis가 주기적으로 스캔해서 삭제

TTL은 Lazy, Active Expiration으로 인해 만료된다고 바로 삭제되는 것이 아닌 약간의 지연시간이 있습니다.

#### 5.  I/O 멀티플렉싱
I/O 멀티플렉싱이란 단일 프로세스, 혹은 스레드가 여러 I/O 작업(여러 개의 소켓, 클라이언트들에게서 오는 요청들)을 동시에 모니터링할 수 있도록 해주는 기술입니다. 

여러 file descriptor(fd)의 I/O 상태를 하나의 호출로 확인할 수 있어, non-blocking 모델의 단점을 극복할 수 있습니다(thread가 계속해서 에러 코드 확인 위해 fd 검사하면서 발생하는 CPU 비용 및 사이클 낭비. 동기적으로 polling).

Redis는 I/O 멀티 플렉싱을 도입해서 싱글 스레드로 수만 개의 클라이언트 요청을 효율적으로 처리할 수 있도록 하였습니다.
높은 동시성, 단순한 아키텍처, 원자적 명령 실행을 보장하는 특징을 가지고 있습니다.

Redis 6 이후로 epoll 기반 멀티플렉싱 구조는 유지하였고, 명령 실행은 여전히 싱글 스레드로 처리됩니다.

#### 6. Replication / Cluster 기반 고가용성 지원
1. Replication
    
    - 장애 발생 시 데이터 보호 위해 도입(고가용성, High Availability)
    - 읽기 부하 분산
    
    Redis는 기본적으로 Master - Slave(Replica) 구조로 동작합니다. Slave는 Master로부터 RDB 스냅샷, AOF 로그를 받아 동기화하고 이후에는 Master의 write 명령을 실시간으로 전달받아 반영합니다.
    비동기 복제에서 사용되고 일부 데이터 유실의 가능성이 존재합니다.
    
    Redis는 기본적으로 다음 순서로 동작합니다.

   1. 클라이언트가 Master에 write 요청을 보낸다.
   2. Master가 즉시 메모리에 반영하고 OK 응답을 보낸다.
   3. 그 후에 변화를 Replica에 전송한다.
   
    따라서 Master가 장애가 발생하여 Replica가 최신 상태를 받아오지 못할 때에 유실이 발생할 수 있습니다.
    
    읽기 연산이 많은 서비스의 Read Replica 사용, 장애 대비 Failover 구조에서 활용될 수 있습니다.

2. Cluster
   
    - data sharding
    - 노드 장애 시 자동 Failover
    - 수평 확장
   
    Redis cluster는 데이터를 슬롯으로 나누고 각 노드가 슬롯을 나눠 갖는 구조로 동작합니다.
    Master가 죽으면 Replica가 자동으로 승격되는 구조(이전에도 Redis + Sentinel로 존재)를 갖고 있고(Sentinel 없이)
    클라이언트가 key를 어느 노드로 보내야 하는지 자동으로 판단합니다.
    
    대규모 사용자 트래픽 처리, 수평 확장 가능한 캐시 계층 구축에 활용할 수 있습니다.

#### 7. Pub / Sub + Stream 제공
Redis를 간단한 메시지 브로커처럼 사용하기 위해 제공되는 기능입니다.
굳이 MQ를 도입하지 않고 간단한 메시지를 전송하고 싶어했던 많은 사람들의 요청을 받아서 도입한 기능입니다.

- Publisher : 특정 채널로 메시지 전송
- Subscriber : 채널을 구독하고 메시지를 실시간 수신

메시지를 저장하지 않기 때문에 이전 메시지를 재수신할 수 없습니다. 또한 방송같은 실시간 알림에 적합합니다.

#### 8. 다양한 Eviction 정책 지원
메모리가 가득 찼을 때 어떤 키를 지울지 선택할 수 있도록 하기 위해 다양한 eviction 정책을 지원합니다.


#### 9. Memcached와 차이점
이에 대해 antirez는 다음과 같이 설명했습니다.
1. Memcached는 영구적이지 않다. 그들의 목적은 단순히 캐시를 사용하는 것이라 저장은 지원하지 않지만 Redis는 앱의 메인DB로도 사용될 수 있다.
2. Memcached와 마찬가지로 key-value 모델을 사용하지만, key는 String이어도 value는 list, set, 그리고 intersection, set/get n-th element, pop/push와 같이 복잡한 동작일 수 있다. list를 message queue처럼 사용할 수 있다.

### 1.5 언제 사용하고, 언제 사용하지 말아야할까?
Redis는 캐시, 세션 저장소, 실시간 랭킹, 메시지 큐 등 데이터의 접근 속도가 중요하고, 데이터 일관성을 유지해야 하는 상황에서 사용해야 합니다.

반면 영구적인 데이터 저장소가 필요하거나 매우 복잡한 쿼리를 자주 수행해야 하는 경우에는 RDB나 다른 NoSQL을 고려하는 것이 좋습니다.

예를 들어 거래기록을 관리해야하는 은행 시스템에서는 0.1초만 서버가 죽어도 수천, 수만건의 거래 기록이 날라갈 수 있습니다. 따라서 이러한 정보들을 다룰 때에 Redis 사용은 권장되지 않습니다.
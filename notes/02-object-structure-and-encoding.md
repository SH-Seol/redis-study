# 2. Redis 객체 구조(Object) & Encoding - 데이터는 어떻게 저장될까?

---

제가 이전에 Redis 0.1버전부터 코드를 분석했던 경험이 있습니다. 그 때 분석하면서 느꼈던 것은 Redis는 사용자의 편의를 중시합니다.
그래서 조회와 같은 기능을 위해 메모리를 일부 추가로 사용하는 것도 마다하지 않습니다.

그런데 메모리 효율도 중시합니다. 매우 컴팩트하게 메모리를 사용하고자 하는 노력들이 보였습니다. Note 2에서 아마 제가 이렇게 생각하게 되었던 이유들을 볼 수 있을 것 같습니다.


### 목차
1. [Redis Object 구조체 분석](#2-1-redis-object-구조체-분석)
2. [SDS(Simple Dynamic String) 구조](#2-2-sdssimple-dynamic-string-구조)
3. [내부 Encoding 종류](#2-3-내부-encoding-종류)
4. [Encoding 자동 변환](#2-4-encoding-자동-변환)

---
## 2-1 Redis Object 구조체 분석
2번째 노트에서는 redis의 객체 구조와 encoding, 데이터가 어떻게 저장될지를 알아보려고 합니다.
저번 overview와 다르게 이제는 redis의 c코드들을 보면서 공부해나가보려고 합니다.

### Robj 코드 분석
먼저 redisObject, robj입니다.

robj는 key와 연결된 value를 저장하는 핵심 구조체입니다. Redis의 모든 데이터 타입은 메모리상에서 robj 구조체로 관리됩니다.

이 구조체는 실제 데이터, value 자체보다는 메타데이터를 담고 있고, redis의 메모리 관리, 데이터 타입 처리, 캐시 정책 구현의 기반이 됩니다.


```c
//server.c
struct redisObject {
    unsigned type:4; //4bit임을 나타내는 것
    unsigned encoding:4;
    unsigned lru:LRU_BITS; /* LRU time (relative to global lru_clock) or
                            * LFU data (least significant 8 bits frequency
                            * and most significant 16 bits access time). */
    unsigned iskvobj : 1;   /* 1 if this struct serves as a kvobj base */
    unsigned expirable : 1; /* 1 if this key has expiration time attached.
                             * If set, then this object is of type kvobj */
    unsigned refcount : OBJ_REFCOUNT_BITS;
    void *ptr;
};
```

`type`은 객체의 실제 데이터 타입을 명시합니다. 이 값을 어떤 데이터 타입으로 다룰지 결정하는 것이죠.
`REDIS_STRING, REDIS_LIST, REDIS_HASH`등이 그 예입니다.

`encoding`은 데이터가 실제로 저장된 방식을 나타냅니다. `SDS, ZIPLIST, HT`를 예시로 들 수 있겠네요.
메모리 효율성을 위해 Redis가 데이터를 압축해 저장했는지를 확인합니다.

`lru`는 메모리가 부족할 경우 만료되지 않은 키 중 무엇을 삭제할지 결정하는데 사용됩니다. LRU나 LFU 알고리즘 구현을 위한 시간/빈도 정보가 있습니다.

`iskvobj`는 key-value object의 기반역할을 하는지 나타냅니다.

`expirable`은 만료 시간, TTL이 설정되어 있는지를 나타냅니다.

`refcount`는 이 객체를 참조하는 곳이 얼마나 있는지를 나타냅니다. Object sharding 메커니즘을 구현하여 메모리를 절약한다고 합니다.

`*ptr`은 실제 데이터 구조체를 가리키는 포인터입니다. encoding에 따라 SDS, ziplist 등을 가리킵니다.

```c
robj *createObject(int type, void *ptr) {
    robj *o = zmalloc(sizeof(*o));
    o->type = type;
    o->encoding = OBJ_ENCODING_RAW;
    o->ptr = ptr;
    o->refcount = 1;
    o->lru = 0;
    o->iskvobj = 0;
    o->expirable = 0;
    return o;
}
```
이 내용은 기본적인 object 생성과정인데요. 메모리 할당하고 기본적인 설정을 합니다.
새로 생성하는 것이다보니 refcount는 1로 설정하네요.

### refcount와 메모리 관리
Redis에서 `refcount`는 메모리 관리를 위해 내부 객체가 몇 개의 다른 객체에 의해 참조되고 있는지를 나타내는 카운터입니다.
쉽게 말하자면 이 객체가 몇 곳에서 사용되고 있는지 나타냅니다.
이는 참조가 없을 때 자동으로 메모리를 해제하는 데 사용되는 프로그래밍 기법인 Reference Counting을 구현한 것입니다.

객체 생명주기 관리(GC)에 사용됩니다. refcount가 0이 될 때만 객체가 메모리에서 해제됩니다.
또한 여러 키가 하나의 값(객체)을 안전하게 공유할 수 있는 기반을 제공합니다.

새로운 객체가 생성되면 refcount = 1입니다.
또 다른 키가 해당 값을 가리키면 `increRefCount()`, 다른 키가 삭제되거나 사용이 끝나면 `decrRefCount()`,
실제로 refcount == 0이 되는 순간 `free()`가 수행됩니다.

```c
void incrRefCount(robj *o) {
    if (o->refcount < OBJ_FIRST_SPECIAL_REFCOUNT) {
        o->refcount++;
    } else {
        if (o->refcount == OBJ_SHARED_REFCOUNT) {
            /* Nothing to do: this refcount is immutable. */
        } else if (o->refcount == OBJ_STATIC_REFCOUNT) {
            serverPanic("You tried to retain an object allocated in the stack");
        }
    }
}

void decrRefCount(robj *o) {
    if (o->refcount == OBJ_SHARED_REFCOUNT)
        return; /* Nothing to do: this refcount is immutable. */

    if (unlikely(o->refcount <= 0)) {
        serverPanic("illegal decrRefCount for object with: type %u, encoding %u, refcount %d",
            o->type, o->encoding, o->refcount);
    }

    if (--(o->refcount) == 0) {
        if (o->ptr != NULL) {
            switch(o->type) {
            case OBJ_STRING: freeStringObject(o); break;
            case OBJ_LIST: freeListObject(o); break;
            case OBJ_SET: freeSetObject(o); break;
            case OBJ_ZSET: freeZsetObject(o); break;
            case OBJ_HASH: freeHashObject(o); break;
            case OBJ_MODULE: freeModuleObject(o); break;
            case OBJ_STREAM: freeStreamObject(o); break;
            default: serverPanic("Unknown object type"); break;
            }
        }
        zfree(o);
    }
}
```
refcount는 공유객체, 복잡한 자료 구조 내부 요소 등에서 특히 중요하고, 참조 수 증감이 정확해야 메모리 누수가 발생하지 않습니다.

### Shared Object
Redis는 매우 많은 작고 반복되는 값을 사용합니다. 자주 등장하는 정수 값들(ex. 1, 2, 3 등)이 대표적인 예시입니다.
이 값들을 계속 새로운 robj로 생성하면 메모리 낭비가 발생하게 됩니다. 그래서 Redis는 **자주 쓰는 값**들을 미리 생성해놓고 모두 공유할 수 있도록 설계했습니다.

```c
/* Set a special refcount in the object to make it "shared":
 * incrRefCount and decrRefCount() will test for this special refcount
 * and will not touch the object. This way it is free to access shared
 * objects such as small integers from different threads without any
 * mutex.
 *
 * A common pattern to create shared objects:
 *
 * robj *myobject = makeObjectShared(createObject(...));
 *
 */
robj *makeObjectShared(robj *o) {
    serverAssert(o->refcount == 1);
    o->refcount = OBJ_SHARED_REFCOUNT;
    return o;
}
```
위 코드는 공유 객체로 설정하는 과정입니다. 해당 객체의 refcount를 설정값으로 변경하여 이 객체가 공유 객체임을 flag로 나타내는 것이죠.
refcount 섹션에서
```c
if (o->refcount == OBJ_SHARED_REFCOUNT)
        return
```
이러한 내용이 있었죠. 이것과 연관지어 볼 수 있는 내용입니다.

그렇다면 왜 이런 디자인을 했을까요?

- 메모리 절약
- 속도
- 안정성

이렇게 3가지로 요약이 가능할 것 같습니다.
자주 사용하는 값들은 하나로 처리할 수 있도록 하여 메모리 절약,
incr/decr 비용을 줄이고 share object인 경우 refcount 계산 자체를 하지 않도록 하고,
I/O 멀티스레드에서 refcount++ 과정에서 race condition이 발생할 수 있는데 이를 회피하기 위함입니다.

shared object이면 refcount가 변경되지 않으므로 lock-free하게 공유 가능하다는 것이죠.

---
## 2-2 SDS(Simple Dynamic String) 구조
SDS입니다. SDS는 Redis 0.1버전에도 존재했던 파일입니다. 개인적으로 어떤 차이가 있을지도 궁금하네요. 
그럼 한번 보겠습니다.

### sds.h
왜 char*가 아닌 sds를 구현하여 사용할까요? 그 이유는 크게 2가지입니다.
1. 속도
2. 효율적인 메모리 관리

C의 문자열인 char*의 경우 문자열 길이를 확인할 때 O(N)으로 전체 순회가 필요합니다.
하지만 sds의 경우는 `len`이란 길이 정보를 저장하여 O(1)로 길이를 조회할 수 있도록 했습니다.
Antirez가 자주 사용하는 정보들은 미리 저장해두는 그러한 철학을 redis에 적용했었는데, 그것의 대표적인 예시가 될 수 있습니다.

```c
static inline size_t sdslen(const sds s) {
    switch (sdsType(s)) {
        case SDS_TYPE_5: return SDS_TYPE_5_LEN(s);
        case SDS_TYPE_8:
            return SDS_HDR(8,s)->len;
        case SDS_TYPE_16:
            return SDS_HDR(16,s)->len;
        case SDS_TYPE_32:
            return SDS_HDR(32,s)->len;
        case SDS_TYPE_64:
            return SDS_HDR(64,s)->len;
    }
    return 0;
}
```
위 코드에서 볼 수 있듯, 순회하는 것이 아닌 저장된 len을 바로 리턴하는 모습입니다.

그렇다면 메모리 관리는 어떤 식으로 하는지 확인해보겠습니다.
기존에 C의 경우 문자열을 수정하거나 이어 붙일 때 버퍼의 크기를 수동으로 관리해야했고,
만약 이 과정에서 잘못되면 **버퍼 오버플로우**가 발생할 수 있었습니다.

그러나 Redis에서 SDS를 사용하면서 문자열 수정하기 전에 필요 공간을 자동으로 확인하고, 공간이 부족하면 자동으로 메모리를 재할당합니다.
관련 코드를 보겠습니다.

```c
sds sdscatlen(sds s, const void *t, size_t len) {
    size_t curlen = sdslen(s);

    s = sdsMakeRoomFor(s,len);
    if (s == NULL) return NULL;
    memcpy(s+curlen, t, len);
    sdssetlen(s, curlen+len);
    s[curlen+len] = '\0';
    return s;
}
```
이 코드만 보지만 `sdscat`을 호출하면 모두 `sdscatlen` 함수를 호출합니다.

---

### sds 기본 구조

이번엔 sdshdr을 한번 보겠습니다. 이전에는 sds를 1개의 struct만 두고 관리했다면, 현재는 크기별로 나눠서 관리하네요.
딱 필요한 메모리만 할당하여 절대로 메모리 낭비가 발생하지 않게 하겠다는 의지가 보입니다.
```c
/* Note: sdshdr5 is never used, we just access the flags byte directly.
 * However is here to document the layout of type 5 SDS strings. */
struct __attribute__ ((__packed__)) sdshdr5 {
    unsigned char flags; /* 3 lsb of type, and 5 msb of string length */
    char buf[];
};
struct __attribute__ ((__packed__)) sdshdr8 {
    uint8_t len; /* used */
    uint8_t alloc; /* excluding the header and null terminator */
    unsigned char flags; /* 3 lsb of type, 5 unused bits */
    char buf[];
};
struct __attribute__ ((__packed__)) sdshdr16 {
    uint16_t len; /* used */
    uint16_t alloc; /* excluding the header and null terminator */
    unsigned char flags; /* 3 lsb of type, 5 unused bits */
    char buf[];
};
struct __attribute__ ((__packed__)) sdshdr32 {
    uint32_t len; /* used */
    uint32_t alloc; /* excluding the header and null terminator */
    unsigned char flags; /* 3 lsb of type, 5 unused bits */
    char buf[];
};
struct __attribute__ ((__packed__)) sdshdr64 {
    uint64_t len; /* used */
    uint64_t alloc; /* excluding the header and null terminator */
    unsigned char flags; /* 3 lsb of type, 5 unused bits */
    char buf[];
};
```
이 안에 `len`은 길이 정보, `alloc`은 헤더와 널 종료 문자를 제외한 실제 할당된 메모리 바이트 수,
`flags`는 SDS의 타입 정보를 저장하는 1바이트 필드, `buf[]`실제 문자열 데이터가 저장되는 배열입니다.

#### (1) 구조체가 왜 `__attribute__((__packed__))`일까요?

C 구조체는 기본적으로 정렬(alignment)를 맞추기 위해 중간에 패딩 바이트를 삽입합니다.
그런데 Redis는 메모리를 한 바이트라도 아끼고자 하기 때문에 패딩이 없이 필드가 연속된 메모리로 붙어 있어야 합니다.

#### (2) 왜 len, alloc이 둘 다 존재할까요?

C 문자열의 단점, 확장 비용과 O(n)의 길이 계산을 해결하기 위해 존재합니다.
len은 현재 문자열 길이를 O(1)로 정보를 얻기 위해 있습니다. 
만약 len이 없다면 `strlen()`처럼 전체 탐색을 해야 합니다.

alloc은 buf에 할당된 전체 용량을 나타냅니다. 확장 시 재할당 여부를 판단하기 위해 필요한 것이죠.
남은 공간은 alloc - len 입니다. 
alloc이 없다면 append 할 때마다 매번 realloc해야하고, preallocation(2배 증가)을 할 수 없습니다.
또한 out-of-bounds 위험이 증가하게 됩니다.

즉 읽기(len), 쓰기(alloc) 성능 둘 다 확보하기 위해 두 필드를 분리한 것입니다.

#### (3) header 크기가 메모리 효율에 어떤 영향을 줄까요?
헤더가 커지면 작은 문자열에서도 메모리를 폭발적으로 낭비할 수 있습니다.
Redis의 헤더 크기가 전체 메모리 사용량에 직접적으로 영향을 줄 수 있습니다.

---

### 생성 과정
sds의 생성과정을 보겠습니다. `sdsnew` 계열의 모든 메소드가 `sdsnewlen`을 호출하는데요.
`sdsnewlen`을 한번 확인해보겠습니다.
```c
sds _sdsnewlen(const void *init, size_t initlen, int trymalloc) {
    void *sh;

    char type = sdsReqType(initlen);
    /* Empty strings are usually created in order to append. Use type 8
     * since type 5 is not good at this. */
    if (type == SDS_TYPE_5 && initlen == 0) type = SDS_TYPE_8;
    int hdrlen = sdsHdrSize(type);
    size_t bufsize;

    assert(initlen + hdrlen + 1 > initlen); /* Catch size_t overflow */
    sh = trymalloc?
        s_trymalloc_usable(hdrlen+initlen+1, &bufsize) :
        s_malloc_usable(hdrlen+initlen+1, &bufsize);
    if (sh == NULL) return NULL;

    adjustTypeIfNeeded(&type, &hdrlen, bufsize);
    return sdsnewplacement(sh, bufsize, type, init, initlen);
}
```
`char type = sdsReqType(initlen);`타입을 먼저 파악을 합니다. HDR5, 8, 16, 32, 64 무엇인지 먼저 파악하고,
만약 TYPE이 5이면 나중에 append와 같은 과정에서 호환을 위해 8로 수정합니다.

다음은 sdsReqType입니다.
```c
char sdsReqType(size_t string_size) {
    if (string_size < 1 << 5) return SDS_TYPE_5;
    if (string_size <= (1 << 8) - sizeof(struct sdshdr8) - 1) return SDS_TYPE_8;
    if (string_size <= (1 << 16) - sizeof(struct sdshdr16) - 1) return SDS_TYPE_16;
#if (LONG_MAX == LLONG_MAX)
    if (string_size <= (1ll << 32) - sizeof(struct sdshdr32) - 1) return SDS_TYPE_32;
    return SDS_TYPE_64;
#else
    return SDS_TYPE_32;
#endif
}
```

```c
sh = trymalloc?
        s_trymalloc_usable(hdrlen+initlen+1, &bufsize) :
        s_malloc_usable(hdrlen+initlen+1, &bufsize);
```
이 과정은 실제 메모리를 할당하는 과정입니다.

`adjustTypeIfNeeded(&type, &hdrlen, bufsize);`그런 뒤에 만약 할당된 실제 usable size를 보고 type을 다시 조정할 수 있습니다.

---

### 확장 과정
이번엔 확장 과정입니다. 위에서 setlen을 하면서 할당된 메모리 공간을 확장하는 과정은 간략하게 보았으니
메모리 재할당, 특히 메모리 doubling 전략을 보여주는 메소드를 가져왔습니다.

```c
sds _sdsMakeRoomFor(sds s, size_t addlen, int greedy) {
    void *sh, *newsh;
    size_t avail = sdsavail(s);
    size_t len, newlen, reqlen;
    char type, oldtype = sdsType(s);
    int hdrlen;
    size_t bufsize, usable;
    int use_realloc;

    /* Return ASAP if there is enough space left. */
    if (avail >= addlen) return s;

    len = sdslen(s);
    sh = (char*)s-sdsHdrSize(oldtype);
    reqlen = newlen = (len+addlen);
    assert(newlen > len);   /* Catch size_t overflow */
    if (greedy == 1) {
        if (newlen < SDS_MAX_PREALLOC)
            newlen *= 2;
        else
            newlen += SDS_MAX_PREALLOC;
    }

    type = sdsReqType(newlen);

    /* Don't use type 5: the user is appending to the string and type 5 is
     * not able to remember empty space, so sdsMakeRoomFor() must be called
     * at every appending operation. */
    if (type == SDS_TYPE_5) type = SDS_TYPE_8;

    hdrlen = sdsHdrSize(type);
    assert(hdrlen + newlen + 1 > reqlen);  /* Catch size_t overflow */
    use_realloc = (oldtype == type);
    if (use_realloc) {
        newsh = s_realloc_usable(sh, hdrlen + newlen + 1, &bufsize, NULL);
        if (newsh == NULL) return NULL;
        s = (char*)newsh + hdrlen;
        if (adjustTypeIfNeeded(&type, &hdrlen, bufsize)) {
            memmove((char *)newsh + hdrlen, s, len + 1);
            s = (char *)newsh + hdrlen;
            s[-1] = type;
            sdssetlen(s, len);
        }
    } else {
        /* Since the header size changes, need to move the string forward,
         * and can't use realloc */
        newsh = s_malloc_usable(hdrlen + newlen + 1, &bufsize);
        if (newsh == NULL) return NULL;
        adjustTypeIfNeeded(&type, &hdrlen, bufsize);
        memcpy((char*)newsh+hdrlen, s, len+1);
        s_free(sh);
        s = (char*)newsh+hdrlen;
        s[-1] = type;
        sdssetlen(s, len);
    }
    usable = bufsize - hdrlen - 1;
    assert(type == SDS_TYPE_5 || usable <= sdsTypeMaxSize(type));
    sdssetalloc(s, usable);
    return s;
}
```

#### 필요 공간 계산
먼저 볼 내용은 필요 공간을 계산하고 확장 여부를 결정하는 것입니다.
```c
size_t avail = sdsavail(s);
if (avail >= addlen) return s;
```
SDS는 current = len, alloc = 할당된 공간, avail = alloc - len, 즉 append시 남은 공간이 충분하면 바로 종료합니다.

#### Preallocation 정책 (greedy)

```c
if (greedy == 1) {
    if (newlen < SDS_MAX_PREALLOC)
        newlen *= 2;
    else
        newlen += SDS_MAX_PREALLOC;
}
```
Redis는 작은 문자열(`SDS_MAX_PREALLOC` 미만의 크기)의 경우는 용량을 2배 증가시키고
그렇지 않은 경우는 `SDS_MAX_PREALLOC` 단위로 증가시킵니다.
참고로 `SDS_MAX_PREALLOC`은 1MB입니다.

#### 헤더 타입 변경
```c
type = sdsReqType(newlen);
if (type == SDS_TYPE_5) type = SDS_TYPE_8;
```
만약 sds의 타입이 type_5라면 sdshdr8로 변경합니다. 
그 이유는 sdshdr5는 append가 불리하기 때문입니다. 왜 불리할까요? 

간단하게 정리하자면 hdr5는 len, alloc이 없습니다.
그러다 보니 헤더가 hdr8은 최소 3바이트이지만 hdr5는 1바이트이구요.
완전히 다르다보니 다른 타입으로 casting이 불가능합니다.
그리고 Redis 내부에서도 sdshdr5를 만드는 경우가 거의 없습니다.
다만 길이가 매우 짧은 문자열을 만들 때 sdshdr5로 구분될 수 있기 때문에 존재하는 구조체입니다.

#### realloc 결정 로직
```c
use_realloc = (oldtype == type);
```
여기서 oldtype과 같으면 realloc을 하고, 타입이 달라지면 새 블록을 malloc 후 memcpy를 합니다.

realloc은 기존 블록 끝에서 확장되므로 비용이 적지만, 헤더 타입이 바뀌면 레이아웃 전체가 달라지므로 새 메모리를 만들어야 합니다.

#### adjustTypeIfNeeded()
```c
//sds.h -> sdsMakeRoomFor()
if (adjustTypeIfNeeded(&type, &hdrlen, bufsize)) {
    memmove((char *)newsh + hdrlen, s, len + 1);
    s = (char *)newsh + hdrlen;
    s[-1] = type;
    sdssetlen(s, len);
}

//sds.h
static inline int adjustTypeIfNeeded(char *type, int *hdrlen, size_t bufsize) {
    size_t usable = bufsize - *hdrlen - 1;
    if (*type != SDS_TYPE_5 && usable > sdsTypeMaxSize(*type)) {
        *type = sdsReqType(usable);
        *hdrlen = sdsHdrSize(*type);
        return 1;
    }
    return 0;
}
```
여기서는 실제로 malloc이 더 큰 usable 공간을 주었는지 확인한 후 더 큰 헤더타입을 쓰는게 효과적이면 변경합니다.

이 최적화는 실제로 Redis 성능에 큰 차이를 주는 것은 아니지만 **디테일이 살아있는 엔지니어링**의 사례입니다.
#### alloc 갱신
```c
usable = bufsize - hdrlen - 1;
sdssetalloc(s, usable);
```
SDS의 핵심은 문자열 길이인 len, 얼마나 메모리가 확보되어 있는지를 나타내는 alloc입니다.

append가 빠른 이유는 alloc을 미리 크게 유지하기 때문입니다. 
이 과정에서 마지막에 반드시 alloc을 업데이트 합니다.

---

### Slicing
Slicing은 특별한 것은 없습니다.
```c
sds sdstrim(sds s, const char *cset) {
    char *end, *sp, *ep;
    size_t len;

    sp = s;
    ep = end = s+sdslen(s)-1;
    while(sp <= end && strchr(cset, *sp)) sp++;
    while(ep > sp && strchr(cset, *ep)) ep--;
    len = (ep-sp)+1;
    if (s != sp) memmove(s, sp, len);
    s[len] = '\0';
    sdssetlen(s,len);
    return s;
}

/* Changes the input string to be a subset of the original.
 * It does not release the free space in the string, so a call to
 * sdsRemoveFreeSpace may be wise after. */
void sdssubstr(sds s, size_t start, size_t len) {
    /* Clamp out of range input */
    size_t oldlen = sdslen(s);
    if (start >= oldlen) start = len = 0;
    if (len > oldlen-start) len = oldlen-start;

    /* Move the data */
    if (len) memmove(s, s+start, len);
    s[len] = 0;
    sdssetlen(s,len);
}
```
다만 이제 `memmove()`를 하는 과정이 존재합니다.
이는 buffer가 서로 겹칠 수 있다는 전제를 처리할 수 있습니다.

또한 버퍼(alloc)는 감소는 절대 하지 않습니다. 
이유로는 append가 발생했을 때 성능 최적화가 있겠습니다.

Java StringBuilder와 비교를 해보면 java의 sb는 substring()을 하면 새로운 객체를 생성하여 free space가 없지만
Redis의 sds는 메모리 재활용을 더 철저히 합니다.

---

### Free
할당 해제입니다. 간단합니다.
```c
void sdsfree(sds s) {
    if (s == NULL) return;
    s_free((char*)s-sdsHdrSize(s[-1]));
}
```
s가 NULL인 경우는 아무것도 하지 않지만 그 외에는 할당해제를 하는 모습입니다.

---
## 2-3 내부 Encoding 종류

이 파트는 Redis가 메모리 사용량을 줄이고 성능을 극대화하기 위해 데이터를 저장하는 내부 표현 방식을 다뤄보겠습니다.

앞서 보았던 robj를 다시 가져와 보겠습니다.

```c
//server.c
struct redisObject {
    unsigned type:4; //4bit임을 나타내는 것
    unsigned encoding:4;
    unsigned lru:LRU_BITS; /* LRU time (relative to global lru_clock) or
                            * LFU data (least significant 8 bits frequency
                            * and most significant 16 bits access time). */
    unsigned iskvobj : 1;   /* 1 if this struct serves as a kvobj base */
    unsigned expirable : 1; /* 1 if this key has expiration time attached.
                             * If set, then this object is of type kvobj */
    unsigned refcount : OBJ_REFCOUNT_BITS;
    void *ptr;
};
```

여기서 `type` 변수는 객체의 실제 데이터 타입을 명시한다고 했습니다. 
```c
//server.h

/* The actual Redis Object */
#define OBJ_STRING 0    /* String object. */
#define OBJ_LIST 1      /* List object. */
#define OBJ_SET 2       /* Set object. */
#define OBJ_ZSET 3      /* Sorted set object. */
#define OBJ_HASH 4      /* Hash object. */
#define OBJ_TYPE_BASIC_MAX 5 /* Max number of basic object types. */
#define OBJ_MODULE 5    /* Module object. */
#define OBJ_STREAM 6    /* Stream object. */
#define OBJ_TYPE_MAX 7  /* Maximum number of object types */
```
String, List, Hash 등 어떤 type인지를 나타냅니다.


그리고 `encoding` 변수는 데이터가 실제로 저장된 방식을 나타냅니다.
```c
#define OBJ_ENCODING_RAW 0     /* Raw representation */
#define OBJ_ENCODING_INT 1     /* Encoded as integer */
#define OBJ_ENCODING_HT 2      /* Encoded as hash table */
#define OBJ_ENCODING_ZIPMAP 3  /* No longer used: old hash encoding. */
#define OBJ_ENCODING_LINKEDLIST 4 /* No longer used: old list encoding. */
#define OBJ_ENCODING_ZIPLIST 5 /* No longer used: old list/hash/zset encoding. */
#define OBJ_ENCODING_INTSET 6  /* Encoded as intset */
#define OBJ_ENCODING_SKIPLIST 7  /* Encoded as skiplist */
#define OBJ_ENCODING_EMBSTR 8  /* Embedded sds string encoding */
#define OBJ_ENCODING_QUICKLIST 9 /* Encoded as linked list of listpacks */
#define OBJ_ENCODING_STREAM 10 /* Encoded as a radix tree of listpacks */
#define OBJ_ENCODING_LISTPACK 11 /* Encoded as a listpack */
#define OBJ_ENCODING_LISTPACK_EX 12 /* Encoded as listpack, extended with metadata */
```

`SDS, QuickList`등이 대표적이고 `SDS`는 저희가 정리한 내용이죠.

우리가 2-3에서 주목할 것은 바로 encoding에 관한 내용입니다.
encoding을 하나씩 간략하게 보고 `tryObjectEncoding()`을 확인해서 어떤 과정으로 encoding을 진행하는지 보겠습니다.

- `RAW`
  - 일반적인 sds 포인터를 그대로 저장
1. 메모리 절약용(compact)
- `INT`
  - 정수값을 integer로 저장하는 문자열 인코딩 최적화
  - "100"을 sds가 아닌 int로 저장
- `EMBSTR`
  - 짧은 문자열 저장할 때 robj + sds가 한번에 할당되는 구조
  - 할당/해제 비용 낮고 캐시 친화적
- `INTSET`
  - Set 객체가 모두 int일 때 사용
  - 작은 정수 집합을 compact하게 저장

2. 성능 중심(lookup / range)
- `HT`
  - dict 기반의 해시 테이블 인코딩
  - HSET, HGET 등을 사용하는 일반적인 해시 구조
- `SKIPLIST`
  - 정렬된 데이터를 위한 계층적 포인터 구조
  - SortedSet(ZSet)의 range query 등을 빠르게 처리
- `QUICKLIST`
  - Redis List의 실제 구현
  - LinkedList + ZipList/Listpack 혼합 구조로 메모리 효율 + 빠른 삽입/삭제

3. 과거 자료(deprecated)
- `ZIPMAP (현재는 사용 X)`
  - 작은 Hash를 위한 경량 메모리 구조
- `LINKEDLIST (현재는 사용 X)`
  - 과거 Redis List가 사용하던 연결 리스트
- `ZIPLIST (현재는 사용 X)`
  - 작은 List/Hash/ZSet을 위한 메모리 구조
  - ListPack이 계승

4. 전용 데이터 구조
- `STREAM`
  - Redis Stream 전용 인코딩
  - 메시지를 listpack 형태로 묶어 저장하는 append-only 구조
- `LISTPACK`
  - ZipList 대체
  - 작은 데이터 리스트 compact하게 저장하는 연속 메모리 구조
  - 삽입, 삭제에 안정적
- `LISTPACK_EX`
  - Stream 등에서 사용하는 확장된 Listpack 구조
  - 주로 Stream Entry 저장용 최적화

---

## 왜 Zipmap, Ziplist는 현재 사용을 안할까? - 왜 ListPack을 사용할까?

먼저 Zipmap, Ziplist을 알아보죠.

### 1. Zipmap

**Zipmap의 특징**

1. 아주 작은 hash를 최소 메모리로 저장하기 위한 O(N) 구조
```c
/* String -> String Map data structure optimized for size.
 * This file implements a data structure mapping strings to other strings
 * implementing an O(n) lookup data structure designed to be very memory
 * efficient.
 *
 * The Redis Hash type uses this data structure for hashes composed of a small
 * number of elements, to switch to a hash table once a given number of
 * elements is reached.
```
`zipmap.c`의 주석에 있는 내용입니다. 주석 안에서 이미 hash를 최소 메모리로 저장하기 위한 구조라고 설명을 하고 있습니다.

2. 완전 연속 메모리 구조
```c
/* Memory layout of a zipmap, for the map "foo" => "bar", "hello" => "world":
 *
 * <zmlen><len>"foo"<len><free>"bar"<len>"hello"<len><free>"world"
 *
 * <zmlen> is 1 byte length that holds the current size of the zipmap.
 */
 
 /* Create a new empty zipmap. */
unsigned char *zipmapNew(void) {
    unsigned char *zm = zmalloc(2);

    zm[0] = 0; /* Length */
    zm[1] = ZIPMAP_END;
    return zm;
}
```
위 내용은 주석 일부 발췌와 `zipmapNew()` 코드입니다. 
코드를 보시면 zipmap을 새로 생성을 했을 때, malloc을 한번만 진행합니다.
완전 연속 메모리 구조이기 때문에 메모리 효율이 좋습니다.

3. 길이 가변 인코딩

```c
#define ZIPMAP_BIGLEN 254

/* The following macro returns the number of bytes needed to encode the length
 * for the integer value _l, that is, 1 byte for lengths < ZIPMAP_BIGLEN and
 * 5 bytes for all the other lengths. */
#define ZIPMAP_LEN_BYTES(_l) (((_l) < ZIPMAP_BIGLEN) ? 1 : sizeof(unsigned int)+1)

/* Encode the length 'l' writing it in 'p'. If p is NULL it just returns
 * the amount of bytes required to encode such a length. */
static unsigned int zipmapEncodeLength(unsigned char *p, unsigned int len) {
    if (p == NULL) {
        return ZIPMAP_LEN_BYTES(len);
    } else {
        if (len < ZIPMAP_BIGLEN) {
            p[0] = len;
            return 1;
        } else {
            p[0] = ZIPMAP_BIGLEN;
            memcpy(p+1,&len,sizeof(len));
            memrev32ifbe(p+1);
            return 1+sizeof(len);
        }
    }
}
```
코드 내용을 간략하게 정리해보면 254 크기로 정해진 `ZIPMAP_BIGLEN`보다 작은 경우
1byte를, 그 외에 큰 경우 5byte를 사용한다는 의미입니다. 
p[0]의 크기가 이미 1byte이고, 그 이후 sizeof(len)인데 int의 크기가 4byte이므로 5byte를 사용하여 저장한다는 의미이죠.
결과적으로 길이가 작으면 1byte, 크면 5byte를 사용하여 인코딩을 합니다.

4. free 공간 재활용 시도

```c
unsigned char *zipmapSet(unsigned char *zm, unsigned char *key, unsigned int klen, unsigned char *val, unsigned int vlen, int *update) {
    unsigned int zmlen, offset;
    unsigned int freelen, reqlen = zipmapRequiredLength(klen,vlen);
    unsigned int empty, vempty;
    unsigned char *p;

    freelen = reqlen;
    if (update) *update = 0;
    p = zipmapLookupRaw(zm,key,klen,&zmlen);
    if (p == NULL) {
        /* Key not found: enlarge */
        zm = zipmapResize(zm, zmlen+reqlen);
        p = zm+zmlen-1;
        zmlen = zmlen+reqlen;

        /* Increase zipmap length (this is an insert) */
        if (zm[0] < ZIPMAP_BIGLEN) zm[0]++;
    } else {
        /* Key found. Is there enough space for the new value? */
        /* Compute the total length: */
        if (update) *update = 1;
        freelen = zipmapRawEntryLength(p);
        if (freelen < reqlen) {
            /* Store the offset of this key within the current zipmap, so
             * it can be resized. Then, move the tail backwards so this
             * pair fits at the current position. */
            offset = p-zm;
            zm = zipmapResize(zm, zmlen-freelen+reqlen);
            p = zm+offset;

            /* The +1 in the number of bytes to be moved is caused by the
             * end-of-zipmap byte. Note: the *original* zmlen is used. */
            memmove(p+reqlen, p+freelen, zmlen-(offset+freelen+1));
            zmlen = zmlen-freelen+reqlen;
            freelen = reqlen;
        }
    }

    /* We now have a suitable block where the key/value entry can
     * be written. If there is too much free space, move the tail
     * of the zipmap a few bytes to the front and shrink the zipmap,
     * as we want zipmaps to be very space efficient. */
    empty = freelen-reqlen;
    if (empty >= ZIPMAP_VALUE_MAX_FREE) {
        /* First, move the tail <empty> bytes to the front, then resize
         * the zipmap to be <empty> bytes smaller. */
        offset = p-zm;
        memmove(p+reqlen, p+freelen, zmlen-(offset+freelen+1));
        zmlen -= empty;
        zm = zipmapResize(zm, zmlen);
        p = zm+offset;
        vempty = 0;
    } else {
        vempty = empty;
    }

    /* Just write the key + value and we are done. */
    /* Key: */
    p += zipmapEncodeLength(p,klen);
    assert(klen < freelen);
    memcpy(p,key,klen);
    p += klen;
    /* Value: */
    p += zipmapEncodeLength(p,vlen);
    *p++ = vempty;
    memcpy(p,val,vlen);
    return zm;
}
```
`zipmapSet()`코드를 전부 가져왔습니다. 이제 하나씩 보겠습니다.

```c
*p++ = vempty; //value 뒤 free 공간 기록
```
zipmap은 value 뒤에 1byte의 free필드를 둡니다.
그래서 같은 key의 value가 다시 커질 경우 재할당 없이 덮어쓰기를 시도합니다.

```c
freelen = zipmapRawEntryLength(p);
        if (freelen < reqlen) {
            /* Store the offset of this key within the current zipmap, so
             * it can be resized. Then, move the tail backwards so this
             * pair fits at the current position. */
            offset = p-zm;
            zm = zipmapResize(zm, zmlen-freelen+reqlen);
            p = zm+offset;

            /* The +1 in the number of bytes to be moved is caused by the
             * end-of-zipmap byte. Note: the *original* zmlen is used. */
            memmove(p+reqlen, p+freelen, zmlen-(offset+freelen+1));
            zmlen = zmlen-freelen+reqlen;
            freelen = reqlen;
        }
        else{
        }
```
위 코드는 실제로는 `if(freelen < reqlen)`의 구현되지 않은 else 파트에 좀 더 집중해보죠. 
(실제 코드에 else부는 없습니다.)
else가 구현되지 않은 이유는 기존 entry 크기(freelen)가 새 value(reqlen)보다 크면 같은 위치에서 재사용하면 된다는 의미에서 그렇습니다.

```c
if (empty >= ZIPMAP_VALUE_MAX_FREE) {
        /* First, move the tail <empty> bytes to the front, then resize
         * the zipmap to be <empty> bytes smaller. */
        offset = p-zm;
        memmove(p+reqlen, p+freelen, zmlen-(offset+freelen+1));
        zmlen -= empty;
        zm = zipmapResize(zm, zmlen);
        p = zm+offset;
        vempty = 0;
    } else {
        vempty = empty; // free 공간 유지
    }
```
`empty >= ZIPMAP_VALUE_MAX_FREE`의 경우 zipmap을 앞으로 당겨 free를 제거하는 모습입니다.
free 공간은 entry 내부에서만 사용 가능하고, 다른 entry와 공유되거나 부분 재활용되지 않습니다.

결론적으로 zipmap은 value 변경 시 재할당을 줄이기 위해 entry 내에 free공간을 유지하지만, 재활용 범위가 매우 제한적이며 free가 부족하거나 과도할 경우 전체 entry를 이동합니다.

---

**왜 zipmap을 사용하지 않을까?**

1. [모든 연산이 O(N) 선형 스캔](#1-모든-연산이-ON-선형-스캔)
2. [insert / update / delete 시 memmove](#2-insert--update--delete-시-memmove)
3. [길이 정보 분산](#3-길이-정보-분산)
4. [zmlen 필드 신뢰 불가](#4-zmlen-필드-신뢰-불가)
5. [validation 코드가 복잡](#5-validation-코드가-복잡)


#### (1) 모든 연산이 O(N) 선형 스캔

```c
static unsigned char *zipmapLookupRaw(unsigned char *zm, unsigned char *key, unsigned int klen, unsigned int *totlen) {
    unsigned char *p = zm+1, *k = NULL;
    unsigned int l,llen;

    while(*p != ZIPMAP_END) {
        unsigned char free;

        /* Match or skip the key */
        l = zipmapDecodeLength(p);
        llen = zipmapEncodeLength(NULL,l);
        if (key != NULL && k == NULL && l == klen && !memcmp(p+llen,key,l)) {
            /* Only return when the user doesn't care
             * for the total length of the zipmap. */
            if (totlen != NULL) {
                k = p;
            } else {
                return p;
            }
        }
        p += llen+l;
        /* Skip the value as well */
        l = zipmapDecodeLength(p);
        p += zipmapEncodeLength(NULL,l);
        free = p[0];
        p += l+1+free; /* +1 to skip the free byte */
    }
    if (totlen != NULL) *totlen = (unsigned int)(p-zm)+1;
    return k;
}
```
위 코드를 보시면 while문을 통해 p를 이동시키며 선형으로 넘어가는 것을 보실 수 있습니다.
key를 찾을 때 처음부터 끝까지 순차 탐색을 진행하는 것이죠. 또한 hash index마저 존재하지 않습니다.


O(N)은 N의 크기가 작으면 몰라도 조금이라도 커지면 기능이 예측하기 어려워질 정도로 느려지는 단점은 redis의 철학과 맞지 않는 모습이죠.

#### (2) insert / update / delete 시 memmove

`zipmapSet()`, `zimmapDel()` 메소드를 모두 보면 `memmove()` 가 존재합니다.

```c
//zipmapSet()
if (freelen < reqlen) {
    memmove(p+reqlen, p+freelen, zmlen-(offset+freelen+1));
}
    
if (empty >= ZIPMAP_VALUE_MAX_FREE) {
    memmove(p+reqlen, p+freelen, zmlen-(offset+freelen+1));
}

//zipmapDel()
if (p) {
    memmove(p, p+freelen, zmlen-((p-zm)+freelen+1));
}
```
memmove를 하는 과정 자체는 결국 메모리 이동 비용이 필요하고
insert, update, delete 모든 과정에 이 과정이 존재하다보니 비용이 커 성능이 좋지 않았습니다.

#### (3) 길이 정보 분산
```c
l = zipmapDecodeLength(p); // key length
...
l = zipmapDecodeLength(p); // value length
```
각 key/value 앞에 길이를 저장합니다.
중앙 인덱스도 없어서 탐색할 때 계속 디코딩을 하죠.

#### (4) zmlen 필드 신뢰 불가
```c
unsigned int zipmapLen(unsigned char *zm) {
    unsigned int len = 0;
    if (zm[0] < ZIPMAP_BIGLEN) {
        len = zm[0];
    } else {
        unsigned char *p = zipmapRewind(zm);
        while((p = zipmapNext(p,NULL,NULL,NULL,NULL)) != NULL) len++;

        /* Re-store length if small enough */
        if (len < ZIPMAP_BIGLEN) zm[0] = len;
    }
    return len;
}
```
위 코드에서 `zm[0]`이 의미하는 것이 zmlen입니다.
`ZIPMAP_BIGLEN`은 값이 254이고 `zm[0]`은 1byte입니다.
즉 `zm[0]`의 값이 0~253이면 정확한 entry 개수, 254면 개수가 많으니 직접 세라는 것을 의미하고, 255면
`ZIPMAP_END`를 의미합니다.
결국 254 미만일 때만 신뢰할 수 있는 값인 것이죠.

254인 경우에는 헤더에 정확한 길이 정보가 없습니다. 그래서 처음부터 끝까지 순회해야하고 직접 엔트리 개수를 계산합니다.
그러다보니 `zm[0]`이 254 이상이면 실제 값이 저장이 되지 않습니다.


#### (5) validation 코드가 복잡

```c
while(*p != ZIPMAP_END) {
    s = zipmapGetEncodedLengthSize(p);
    if (OUT_OF_RANGE(p+s)) return 0;
    ...
    e = *p++;
    p += l+e;
}
```
위 코드는 `zipmapValidateIntegrity()` 코드의 일부를 발췌한 것입니다.
포인터를 이동하는 그러한 과정이 정말 많은데 이 과정에서 잘못될 경우 바로 corrupt하게 됩니다.
boundary check 또한 많기에 구조적으로 이미 fragile한 상태입니다.

---

### 2. Ziplist

**왜 zipmap에서 ziplist로 넘어갔을까?**

- Hash 전용 구조 -> 범용 sequential container
- key–value 암묵 결합 -> 독립 entry
- 단방향 순회 -> 양방향 순회
- 구조 추론 어려움 -> 명시적 entry 메타데이터
- 재사용 불가 -> List / ZSet / Hash 공통 사용

#### (1) Hash 전용 구조 -> 범용 sequential container

zipmap 코드 특징을 간단히 보면
```c
<key><value><key><value>...
```
무조건 key-value 쌍입니다.
hash 전용이구요. List, ZSet, Stream에서 재사용이 불가능합니다.

ziplist에서 설계 변화가 일어났습니다.
```c
<entry><entry><entry>...
```
entry는 값이 하나입니다. List, Hash, ZSet 공통 사용이며, 동일 구조를 여러 타입에서 재사용됩니다.
```c
typedef struct zlentry {
    unsigned int prevrawlen;
    unsigned int lensize;
    unsigned int len;
    unsigned int headersize;
    unsigned char encoding;
    unsigned char *p;
} zlentry;
```
ziplist는 Redis 내부 범용 compact 컨테이너입니다.

#### (2) key-value 암묵 결합 -> 독립 entry

zipmap은 key, value가 구조적으로 분리되지 않고 연속 배치되지만, ziplist는 각 entry가 독립된 구조체로 표현됩니다.
```c
l = zipmapDecodeLength(p);  // key length
p += llen + l;

l = zipmapDecodeLength(p);  // value length
p += zipmapEncodeLength(NULL,l);
free = p[0];
p += l + 1 + free;
```
이렇게 보면 key 뒤 value가 암묵적으로 존재합니다.
반대로 entry는 하나가 완결된 구조라 다른 entry와 독립적이죠.

#### (3) 단방향 순회 -> 양방향 순회

zipmap은 forward iteration만 가능합니다. 
이에 반해 ziplist는 entry가 이전 entry 길이(prevlen)을 보유해서 역방향 탐색이 가능합니다.

- zipmap
```c
unsigned char *zipmapNext(unsigned char *zm, unsigned char **key, unsigned int *klen, unsigned char **value, unsigned int *vlen) {
    if (zm[0] == ZIPMAP_END) return NULL;
    if (key) {
        *key = zm;
        *klen = zipmapDecodeLength(zm);
        *key += ZIPMAP_LEN_BYTES(*klen);
    }
    zm += zipmapRawKeyLength(zm);
    if (value) {
        *value = zm+1;
        *vlen = zipmapDecodeLength(zm);
        *value += ZIPMAP_LEN_BYTES(*vlen);
    }
    zm += zipmapRawValueLength(zm);
    return zm;
}
```
next만 존재하고, prev는 존재하지 않습니다.

- ziplist
```c
unsigned char *ziplistPrev(unsigned char *zl, unsigned char *p) {
    unsigned int prevlensize, prevlen = 0;

    /* Iterating backwards from ZIP_END should return the tail. When "p" is
     * equal to the first element of the list, we're already at the head,
     * and should return NULL. */
    if (p[0] == ZIP_END) {
        p = ZIPLIST_ENTRY_TAIL(zl);
        return (p[0] == ZIP_END) ? NULL : p;
    } else if (p == ZIPLIST_ENTRY_HEAD(zl)) {
        return NULL;
    } else {
        ZIP_DECODE_PREVLEN(p, prevlensize, prevlen);
        assert(prevlen > 0);
        p-=prevlen;
        size_t zlbytes = intrev32ifbe(ZIPLIST_BYTES(zl));
        zipAssertValidEntry(zl, zlbytes, p);
        return p;
    }
} 
```
이를 통해 List, ZSet(sorted set)의 양방향 연산이 가능해졌습니다.

#### (4) 구조 추론 어려움 -> 명시적 entry 메타데이터

zipmap은 분산된 정보를 가지고 있죠.
```c
<len><payload><free>
```
key/ value마다 형식이 다르고 free는 value에만 존재하며 파싱 로직이 복잡하죠.

```c
typedef struct zlentry {
    unsigned int prevrawlensize; /* Bytes used to encode the previous entry len*/
    unsigned int prevrawlen;     /* Previous entry len. */
    unsigned int lensize;        /* Bytes used to encode this entry type/len.
                                    For example strings have a 1, 2 or 5 bytes
                                    header. Integers always use a single byte.*/
    unsigned int len;            /* Bytes used to represent the actual entry.
                                    For strings this is just the string length
                                    while for integers it is 1, 2, 3, 4, 8 or
                                    0 (for 4 bit immediate) depending on the
                                    number range. */
    unsigned int headersize;     /* prevrawlensize + lensize. */
    unsigned char encoding;      /* Set to ZIP_STR_* or ZIP_INT_* depending on
                                    the entry encoding. However for 4 bits
                                    immediate integers this can assume a range
                                    of values and must be range-checked. */
    unsigned char *p;            /* Pointer to the very start of the entry, that
                                    is, this points to prev-entry-len field. */
} zlentry;
```
entry 길이,
이전 entry 길이,
encoding 타입까지 entry 구조 자체가 self-describing합니다.
즉, ziplist는 파싱 안정성과 코드 가독성을 크게 개선했죠.

#### (5) 재사용 불가 -> List / ZSet / Hash 공통 사용
zipmap은 hash 전용이라 redis 내부에서 재사용이 불가능했습니다.
반면 ziplist는 하나의 구조이기에 여러 자료형을 표현할 수 있게 했죠.

```c
// Hash
if (hashTypeGetEncoding(o) == OBJ_ENCODING_ZIPLIST)

// List
if (o->encoding == OBJ_ENCODING_ZIPLIST)

// ZSet
OBJ_ENCODING_ZIPLIST
```
zipmap은 메모리 절약에만 집중한 특수 구조, ziplist는 redis 전체를 위한 범용 compact container였습니다.

**왜 ziplist를 사용하지 않을까?**

ziplist는 redis 전체를 위한 구조로 사용하고자 하는 의도는 좋았습니다만,
구조적 한계로 인한 worst case 성능이 치명적이었습니다.

1. [prevlen overflow](#1-prevlen-overflow)
2. [entry 길이 증가 → 연쇄적인 memmove](#2-entry-길이-증가--연쇄적인-memmove)
3. [insertion O(N) + realloc 폭탄](#3-insertion-on--realloc-폭탄)

#### (1) prevlen overflow
```c
struct zlentry {
    unsigned int prevrawlen;
    unsigned int lensize;
    unsigned int len;
    unsigned int headersize;
    unsigned char encoding;
};
```
`prevrawlen` < 254 인 경우 1byte,
`prevrawlen` >= 254인 경우 5bytes
이전 entry가 커지면 다음 entry의 header 크기가 변합니다.

entry A가 커지면 entry B의 prevlen 크기가 증가하고 entry B 크기가 증가합니다.
entry C의 prevlen도 변경되고 이 구조 변경 과정이 연쇄적으로 발생합니다.
이것이 prevlen cascade update 입니다.

#### (2) entry 길이 증가 → 연쇄적인 memmove

```c
//ziplistInsert()
ziplistResize(zl, newlen);
...
memmove();
```
entry 하나 수정을 하면 뒤 entry 모두 이동을 합니다.
최악의 경우 O(N^2)수준의 연쇄 memmove가 발생합니다.

#### (3) insertion O(N) + realloc 폭탄
ziplist는 완전 연속 메모리 구조입니다.
```c
[entry][entry][entry]...
```
중간 삽입, entry 확장, header 변경의 과정에서 매번 realloc, memmove가 발생합니다.
평균 성능은 괜찮을 수 있지만 worst case의 경우 latency를 예측할 수 없습니다.
이는 결국 redis의 철학, 일관된 성능, 지연 없는 서버와 충돌하죠.

**그렇다면 왜 ListPack일까?**

Redis는 compact하면서도 worst case, 최악의 경우에서도 성능이 예측이 가능한 구조를 선택했습니다.

ListPack의 목표는 다음과 같습니다.

1. [backward length 제거 -> 파싱 안정성 향상](#1-backward-length-제거---파싱-안정성-향상)
2. [overflow / underflow 취약점 제거](#2-overflow--underflow-취약점-제거)
3. [entry 구조 단순화](#3-entry-구조-단순화)
4. [Stream, Quicklist 등 다양한 구조에서 재사용 가능](#4-stream-quicklist-등-다양한-구조에서-재사용-가능)

#### (1) backward length 제거 -> 파싱 안정성 향상

```c
typedef struct {
    /* When string is used, it is provided with the length (slen). */
    unsigned char *sval;
    uint32_t slen;
    /* When integer is used, 'sval' is NULL, and lval holds the value. */
    long long lval;
} listpackEntry;
```
listpack의 구조입니다.

- prevlen을 완전히 제거
- backward traversal의 경우
  - entry를 직접 추론 x
  - index / 외부 구조에 의존

구조 단순화를 통해 안정성 증가를 노린 것입니다.

따라서 listpack의 entry는 단순히 encoding + payload 구조만 갖습니다.
이는 cascade update 구조를 사라지게 했고
entry 수정시 뒤쪽 entry 영향을 안 받아서 노드 간 의존성이 제거되어 구조가 훨씬 단순해졌습니다.

#### (2) overflow / underflow 취약점 제거

ziplist는 가변-length prevlen으로 인해 entry 길이가 커지면 ziplist 전체 재구성에 가까운 작업이 발생했지만,
listpack은 그런 이슈가 없습니다.
실제로 ziplist에는 cascade update가 발생했으니까요.
반면 listpack은 entry 자체만 재작성하면 됩니다.

#### (3) entry 구조 단순화
listpack은 내부 구조가 단순해져서 구현이 명확하고 유지보수가 쉬워졌습니다.
listpack's api:
`lpNext()`, `lpPrev()`, `lpFirst()`, `lpLast()`, `lpLength()`, `lpGet()` 등
- 각 entry 접근 함수가 명확하고 독립적입니다.
- prev / next가 포인터 기반의 복잡한 계산 없이 동작합니다.

#### (4) Stream, Quicklist 등 다양한 구조에서 재사용 가능

redis는 listpack을 다양한 자료구조에서 사용합니다.
특히 stream은 대용량 레코드 기반 구조이지만 listpack을 사용하여 각 stream entry를 compact하게 저장합니다.

### 왜 Stream도 listpack을 사용할까?

```c
typedef struct stream {
    rax *rax;               /* The radix tree holding the stream. */
    uint64_t length;        /* Current number of elements inside this stream. */
    streamID last_id;       /* Zero if there are yet no items. */
    streamID first_id;      /* The first non-tombstone entry, zero if empty. */
    streamID max_deleted_entry_id;  /* The maximal ID that was deleted. */
    uint64_t entries_added; /* All time count of elements added. */
    size_t alloc_size;      /* Total allocated memory (in bytes) by this stream. */
    rax *cgroups;           /* Consumer groups dictionary: name -> streamCG */
    rax *cgroups_ref;       /* Index mapping message IDs to their consumer groups. */
    streamID min_cgroup_last_id;  /* The minimum ID of consume group. */
    unsigned int min_cgroup_last_id_valid: 1;
} stream;
```
위는 redis stream의 구조입니다. 그리고 radix tree(rax)의 value로 listpack이 사용되죠.
즉, 한 stream entry는 listpack으로 직렬화된 필드/값 쌍 형태로 저장됩니다.

#### Stream이 listpack을 사용하는 이유
Stream은 다음과 같은 요구사항을 가집니다.

1. 안정적 구조
   
   - stream entry는 append-only, 장시간 저장, AOF와 같이 데이터 무결성이 중요합니다.
   - listpack은 구조 자체가 simple & safe -> corruption에 유리합니다.
   - ziplist는 encoding/prevlen 때문에 취약점 보고 사례가 많았습니다.
2. entry당 key / value가 compact

   - stream entry는 실제로 필드/값 쌍으로 구성됩니다.
   - listpack format은 이 쌍을 연속적으로 저장합니다.
   - 필요시 순회하면서 decoding할 수 있습니다.
3. 범용 구조로 확장성 제공

   - stream 뿐만 아니라 hash, list, zset 등 redis core 자료구조 모두 listpack으로 동일 encoding을 사용하도록 했습니다.
   - 이로 인해 코드 중복이 줄고 내부 일관성이 증가하였습니다.

**번외. 왜 LinkedList는 더 이상 사용하지 않을까?**

LinkedList의 문제
```c
[node] -> [node] -> [node] -> ...
```
캐시 locality가 좋지 않고, 메모리 오버헤드가 큽니다.

redis 관점에서 단점은 cpu cache miss 가 빈번하다는 점,
메모리 사용량이 급증할 수 있다는 점,
작은 데이터에 매우 비효율적이라는 점에서 사용하지 않게 되었습니다.

---

### `tryObjectEncoding()`
이제 인코딩 과정을 한번 확인해보겠습니다.
먼저 어떻게 선택을 하는지 보시죠.
```c
//object.c
robj *tryObjectEncodingEx(robj *o, int try_trim) {
    long value;
    sds s = o->ptr;
    size_t len;

    /* Make sure this is a string object, the only type we encode
     * in this function. Other types use encoded memory efficient
     * representations but are handled by the commands implementing
     * the type. */
    serverAssertWithInfo(NULL,o,o->type == OBJ_STRING);

    /* We try some specialized encoding only for objects that are
     * RAW or EMBSTR encoded, in other words objects that are still
     * in represented by an actually array of chars. */
    if (!sdsEncodedObject(o)) return o;

    /* It's not safe to encode shared objects: shared objects can be shared
     * everywhere in the "object space" of Redis and may end in places where
     * they are not handled. We handle them only as values in the keyspace. */
     if (o->refcount > 1) return o;

    /* Check if we can represent this string as a long integer.
     * Note that we are sure that a string larger than 20 chars is not
     * representable as a 32 nor 64 bit integer. */
    len = sdslen(s);
    if (len <= 20 && string2l(s,len,&value)) {
        /* This object is encodable as a long. */
        if (o->encoding == OBJ_ENCODING_RAW) {
            sdsfree(o->ptr);
            o->encoding = OBJ_ENCODING_INT;
            o->ptr = (void*) value;
            return o;
        } else if (o->encoding == OBJ_ENCODING_EMBSTR) {
            decrRefCount(o);
            return createStringObjectFromLongLongForValue(value);
        }
    }

    /* If the string is small and is still RAW encoded,
     * try the EMBSTR encoding which is more efficient.
     * In this representation the object and the SDS string are allocated
     * in the same chunk of memory to save space and cache misses. */
    if (len <= OBJ_ENCODING_EMBSTR_SIZE_LIMIT) {
        robj *emb;

        if (o->encoding == OBJ_ENCODING_EMBSTR) return o;
        emb = createEmbeddedStringObject(s,sdslen(s));
        decrRefCount(o);
        return emb;
    }

    /* We can't encode the object...
     * Do the last try, and at least optimize the SDS string inside */
    if (try_trim)
        trimStringObjectIfNeeded(o, 0);

    /* Return the original object. */
    return o;
}
```

`tryObjectEncodingEx()`는 String 타입 객체에 한해 가장 메모리 효율적인 encoding으로 재표현을 시도하는 함수입니다.
이 함수는 객체를 바꿀 수 있으면 바꾼다가 아닌, 안전하고 이득이 명확한 경우에만 바꾼다는 보수적인 전략을 따릅니다.

#### (1) 대상 객체 제한

```c
/* Make sure this is a string object, the only type we encode
     * in this function. Other types use encoded memory efficient
     * representations but are handled by the commands implementing
     * the type. */
serverAssertWithInfo(NULL,o,o->type == OBJ_STRING);
```
주석에도 작성되어 있듯, String 객체 전용입니다.
List / Hash / Set 등은 각 타입의 command 레벨에서 따로 처리됩니다.
공통 엔트리 포인트가 아닌 String 전용 최적화 루틴인 것입니다.

#### (2) RAW / EMBSTR 객체만 인코딩 대상

```c
/* We try some specialized encoding only for objects that are
     * RAW or EMBSTR encoded, in other words objects that are still
     * in represented by an actually array of chars. */
    if (!sdsEncodedObject(o)) return o;
```

이미 Int encoding된 객체는 대상이 아닙니다.
실제 문자 배열(SDS)을 가진 객체만 처리합니다.
이는 중복 인코딩을 방지한다는 것이죠.

#### (3) 공유 객체 제외

```c
/* It's not safe to encode shared objects: shared objects can be shared
     * everywhere in the "object space" of Redis and may end in places where
     * they are not handled. We handle them only as values in the keyspace. */
     if (o->refcount > 1) return o;
```
refcount > 1 이라는 것은 여러 곳에서 이미 해당 객체를 참조하고 있다는 의미입니다.
이 경우 encoding을 변경하면 다른 key의 의미가 깨질 수 있으므로 redis는 shared object는 변형하지 않습니다.

#### (4) 정수 인코딩 시도

```c
/* Check if we can represent this string as a long integer.
     * Note that we are sure that a string larger than 20 chars is not
     * representable as a 32 nor 64 bit integer. */
    len = sdslen(s);
    if (len <= 20 && string2l(s,len,&value)) {
        /* This object is encodable as a long. */
        if (o->encoding == OBJ_ENCODING_RAW) {
            sdsfree(o->ptr);
            o->encoding = OBJ_ENCODING_INT;
            o->ptr = (void*) value;
            return o;
        } else if (o->encoding == OBJ_ENCODING_EMBSTR) {
            decrRefCount(o);
            return createStringObjectFromLongLongForValue(value);
        }
    }
```
길이가 20 이하, 문자열이 정수 변환 가능하다면 redis는 Int encoding을 먼저 시도합니다.

왜 int가 최우선일까요?
- sds 포인터 제거
- 메모리가 가장 작음
- 숫자 연산(INCR 등) 즉시 사용 가능

(4-1) Raw -> Int

```c
if (o->encoding == OBJ_ENCODING_RAW) {
            sdsfree(o->ptr);
            o->encoding = OBJ_ENCODING_INT;
            o->ptr = (void*) value;
            return o;
```
sds 메모리를 해제하고, ptr에 정수를 직접 저장합니다. 가장 이상적인 변환 케이스이죠.

(4-2) Embstr -> Int

```c
else if (o->encoding == OBJ_ENCODING_EMBSTR) {
            decrRefCount(o);
            return createStringObjectFromLongLongForValue(value);
        }
```
Embstr은 object + sds가 한 덩어리입니다.
부분 수정이 불가하기에 새로운 객체를 생성하는 것이죠. 기존 객체 refcount가 감소하는 것입니다.
어쩌면 embstr의 구조적 한계가 드러나는 지점이겠네요.

#### (5) 짧은 문자열 -> EMBSTR

```c
/* If the string is small and is still RAW encoded,
     * try the EMBSTR encoding which is more efficient.
     * In this representation the object and the SDS string are allocated
     * in the same chunk of memory to save space and cache misses. */
    if (len <= OBJ_ENCODING_EMBSTR_SIZE_LIMIT) {
        robj *emb;

        if (o->encoding == OBJ_ENCODING_EMBSTR) return o;
        emb = createEmbeddedStringObject(s,sdslen(s));
        decrRefCount(o);
        return emb;
    }
```
문자열이 작고, 아직 RAW의 상태인 경우 EMBSTR로 변환을 시도합니다.
EMBSTR의 목적은
robj + SDS 를 하나의 연속된 메모리 블록에 할당하여
malloc 호출을 1번으로 줄이고, cache locality를 개선하는 것입니다.
#### (6) 더 이상 변환 불가의 경우

```c
/* We can't encode the object...
     * Do the last try, and at least optimize the SDS string inside */
    if (try_trim)
        trimStringObjectIfNeeded(o, 0);
```
encoding을 진행할 수 없지만 sds의 여분 공간(trim)정리를 하는 것입니다.
마지막으로 미세하게 최적화를 진행하는 것이죠.

#### (7) 원본 객체 반환

```c
return o;
```
변환 이득이 없거나, 위험하거나 조건이 맞지 않으면 그래도 유지합니다.

---

## 2-4 Encoding 자동 변환

왜 Redis를 사용하면 자동으로 빠르게 유지가 될까요?
그리고 언제 자동 변환이 일어날까요?

Redis의 특징 중 하나는 데이터가 커졌다가 다시 작아져도,
혹은 형태가 바뀌어도,
성능이 자연스럽게 유지된다는 점입니다.

이는 Redis가 내부적으로 Encoding을 고정하지 않고, 상태에 따라 자동으로 전환하기 때문입니다.

Encoding 자동변환이란 객체의 현재 크기, 형태, 값의 성격에 따라 가장 효율적인 내부 표현을 다시 선택하는 메커니즘입니다.

redis는 한 번 선택한 encoding을 영구히 유지하지 않습니다.

- 문자열이 숫자로 해석이 가능하면 → INT
- 문자열이 짧아지면 → EMBSTR
- 문자열이 커지면 → RAW

이 변환은 문자열을 생성하거나 수정하는 명령 실행 중 발생합니다. 예를 들면 Set, Incr / Decr, Append 등이 있습니다.

이외에도

- Hash가 커지면 → HT
- List가 커지면 → QUICKLIST
- Stream entry가 쌓이면 → LISTPACK_EX

변환이 필요할 때는 현재 상태에 가장 잘 맞는 구조로 계속 이동한다는 것을 보여줍니다.

1. [hash 변환](#1-hash-변환)
2. [list 변환](#2-list-변환)
3. [stream 변환](#3-stream-변환)

#### (1) hash 변환

```c
void hashTypeTryConversion(redisDb *db, kvobj *o, robj **argv, int start, int end) {
    int i;
    size_t sum = 0;

    if (o->encoding != OBJ_ENCODING_LISTPACK && o->encoding != OBJ_ENCODING_LISTPACK_EX)
        return;

    /* We guess that most of the values in the input are unique, so
     * if there are enough arguments we create a pre-sized hash, which
     * might over allocate memory if there are duplicates. */
    size_t new_fields = (end - start + 1) / 2;
    if (new_fields > server.hash_max_listpack_entries) {
        hashTypeConvert(db, o, OBJ_ENCODING_HT);
        dictExpand(o->ptr, new_fields);
        return;
    }

    for (i = start; i <= end; i++) {
        if (!sdsEncodedObject(argv[i]))
            continue;
        size_t len = sdslen(argv[i]->ptr);
        if (len > server.hash_max_listpack_value) {
            hashTypeConvert(db, o, OBJ_ENCODING_HT);
            return;
        }
        sum += len;
    }
    if (!lpSafeToAdd(hashTypeListpackGetLp(o), sum)) {
        hashTypeConvert(db, o, OBJ_ENCODING_HT);
    }
}

void hashTypeConvert(redisDb *db, robj *o, int enc) {
    if (o->encoding == OBJ_ENCODING_LISTPACK) {
        hashTypeConvertListpack(o, enc);
    } else if (o->encoding == OBJ_ENCODING_LISTPACK_EX) {
        hashTypeConvertListpackEx(db, o, enc);
    } else if (o->encoding == OBJ_ENCODING_HT) {
        serverPanic("Not implemented");
    } else {
        serverPanic("Unknown hash encoding");
    }
}
```

간략하게 설명해보죠.

`hashTypeTryConversion()` 이 함수 내부에서는 필드 개수 증가, 필드 또는 값의 길이가 임계값을 초과하는지를 검사합니다.
조건을 만족하면 `hashTypeConvert()`를 호출하는 것이죠. 이 때도 encoding 여부에 따라 필요한 것으로 변환합니다.

#### (2) list 변환

list, 그리고 후술할 stream은 `tryConversion()`이 변환 함수가 아닙니다. entry 정규화 단계이죠.

list는 생성할 때부터 Quicklist 구조를 사용하여 OBJ_ENCODING_QUICKLIST는 변경되지 않습니다.

즉, list에는 다음과 같은 변화만 존재합니다.

- quicklist node 증가 / 분할
- node 내부 listpack 확장 / 축소
- entry의 표현 방식(int / string) 결정

다만 quicklist -> 다른 구조로의 변환은 발생하지 않습니다.

```text
list command
 └─ listTypeTryConversion()   // entry 정규화
 └─ quicklistPush()
     └─ quicklistPushHead / Tail
         └─ listpackAppend
```
여기에서 구조적 의미를 갖는 부분이 바로 quicklistPush()이죠.

```c
/* Wrapper to allow argument-based switching between HEAD/TAIL pop */
void quicklistPush(quicklist *quicklist, void *value, const size_t sz,
                   int where) {
    /* The head and tail should never be compressed (we don't attempt to decompress them) */
    if (quicklist->head)
        assert(quicklist->head->encoding != QUICKLIST_NODE_ENCODING_LZF);
    if (quicklist->tail)
        assert(quicklist->tail->encoding != QUICKLIST_NODE_ENCODING_LZF);

    if (where == QUICKLIST_HEAD) {
        quicklistPushHead(quicklist, value, sz);
    } else if (where == QUICKLIST_TAIL) {
        quicklistPushTail(quicklist, value, sz);
    }
}
```
이 함수는 encoding 선택이나 변환을 전혀 수행하지 않습니다.

이 코드가 보장하는 것은

1. 구조는 항상 quicklist
   - quicklist 포인터 자체가 list의 본체
   - robj->encoding == OBJ_ENCODING_QUICKLIST는 변경되지 않음
2. 압축 node는 직접 건드리지 않음 
   - head / tail node는 항상 uncompressed
   - 삽입 시 decompression 비용 제거
   - 삽입 비용을 예측 가능하게 유지
3. 삽입 위치만 결정
   - 현재 node의 listpack에 append 시도
   - 공간 부족 시 node split
   - 새 node 생성

모두 quicklist 내부 관리 로직일 뿐, 변환이 아닙니다.
quicklist는 공간 효율, 성능 상한을 보장하기에 list는 encoding을 바꾸지 않고
내부 node 단우로만 구조를 조절합니다.

#### (3) stream 변환

앞서 말했듯, Stream에는 encoding 변환이 존재하지 않습니다.
List와 마찬가지로 Stream은 처음부터 끝까지 하나의 encoding을 유지합니다.
- OBJ_ENCODING_STREAM
- 내부 표현: Radix Tree + ListPack

Stream에서 발생하는 변화는 encoding conversion 이 아니라
entry 증가에 따른 내부 listpack 분할과 재배치입니다.

```c
robj *createStreamObject(void) {
    stream *s = streamNew();
    robj *o = createObject(OBJ_STREAM,s);
    o->encoding = OBJ_ENCODING_STREAM;
    return o;
}
```
stream 객체는 생성 시점에 바로 OBJ_ENCODING_STREAM으로 정해집니다.
처음부터 가변 구조가 아닌 최종 구조로 생성되는 것이죠.

```c
Stream (OBJ_ENCODING_STREAM)
 └─ rax (Radix Tree)
     └─ key: master entry ID
     └─ value: listpack
         └─ [entry fields...]
```

- Stream entry는 listpack 단위로 묶여 저장
- 하나의 listpack에는 여러 stream entry가 들어감
- listpack이 커지면 → 새 listpack 생성

Stream에 entry가 추가될 때 호출되는 핵심 로직은 다음입니다.
```c
int streamAppendItem(stream *s, robj **argv, int64_t numfields, streamID *added_id, streamID *use_id, int seq_given)
```

코드를 가져오고자 했는데 너무 길어서 부분 발췌하겠습니다.

1. [Encoding 변경 코드가 존재하지 않음](#1-encoding-변경-코드가-존재하지-않음)
2. [핵심 확장 분기점: 기존 listpack에 붙일 수 있는가](#2-핵심-확장-분기점-기존-listpack에-붙일-수-있는가)
3. [listpack이 가득 찼을 때의 동작](#3-listpack이-가득-찼을-때의-동작)
4. [새 listpack 생성](#4-새-listpack-생성)
5. [Entry는 listpack 내부에만 추가된다](#5-entry는-listpack-내부에만-추가된다)
6. [listpack 기반 확장 흐름 요약](#6-listpack-기반-확장-흐름-요약)
7. [왜 stream은 이 구조를 선택했을까?](#7-왜-stream은-이-구조를-선택했을까)


#### (1) Encoding 변경 코드가 존재하지 않음

함수 전체를 통틀어 아래와 같은 코드는 단 한줄도 등장하지 않습니다.
```c
o->encoding = ...
```
즉 stream 객체는 생성 시점부터 끝까지 `OBJ_ENCODING_STREAM`를 유지합니다.

#### (2) 핵심 확장 분기점: 기존 listpack에 붙일 수 있는가

Stream의 확장 여부는 encoding이 아니라 listpack 용량으로 결정됩니다.

```c
raxSeek(&ri,"$",NULL,0);
if (!raxEOF(&ri)) {
    lp = ri.data;
    lp_bytes = lpBytes(lp);
}
```
이 부분은 radix tree의 마지막 노드입니다.
tail listpack을 가져오는 모습을 볼 수 있죠.

```c
if (lp_bytes + totelelen >= node_max_bytes) {
    new_node = 1;
} else if (server.stream_node_max_entries) {
    int64_t count = lpGetInteger(lp_ele) +
                    lpGetInteger(lpNext(lp,lp_ele));
    if (count >= server.stream_node_max_entries)
        new_node = 1;
}
```

#### (3) listpack이 가득 찼을 때의 동작

이 코드는 listpack이 가득 찼는지 검사하는 모습입니다.

여기서 중요한 점은 판단기준은 오직
- listpack byte size
- listpack entry count
- encoding은 고려대상 x

인 것입니다.

listpack이 가득 찼을 때의 동작은

```c
lp = lpShrinkToFit(lp);
...
lp = NULL;
```
위와 같습니다.
기존 listpack 재구성, encoding 변경, 전체 memmove는 하지 않고 
현재 listpack을 정리(shrink), 그리고 새 listpack 생성 경로로 진입하는 모습이 있네요.

#### (4) 새 listpack 생성

```c
if (lp == NULL) {
    master_id = id;
    streamEncodeID(rax_key,&id);

    lp = lpNew(prealloc);
    lp = lpAppendInteger(lp,1); /* count */
    lp = lpAppendInteger(lp,0); /* deleted */
    lp = lpAppendInteger(lp,numfields);
    ...
    raxInsert(s->rax,rax_key,sizeof(rax_key),lp,NULL);
}
```

이 부분이 stream 확장의 본질입니다.

핵심 포인트로는 기존 구조를 유지한다는 점, 새 listpack을 추가하고 radix tree에 새 노드를 삽입한다는 점입니다.

요약하면 아래와 같은 구조입니다.

```c
[rax]
 ├─ listpack #1
 ├─ listpack #2
 └─ listpack #3 ← 새로 추가
```

#### (5) Entry는 listpack 내부에만 추가된다

실제 entry 추가는 항상 listpack 내부에서만 이루어집니다.

```c
lp = lpAppendInteger(lp,flags);
lp = lpAppendInteger(lp,id.ms - master_id.ms);
lp = lpAppendInteger(lp,id.seq - master_id.seq);
...
lp = lpAppend(lp,value,...);
lp = lpAppendInteger(lp,lp_count);
```
모든 연산은 현재 listpack 내부에서 일어납니다.
다른 listpack에는 영향이 없습니다.
memmove 범위는 listpack 단위로 제한되구요.

#### (6) listpack 기반 확장 흐름 요약

```c
XADD
 └─ streamAppendItem()
     ├─ tail listpack 조회
     ├─ 크기 / entry 수 검사
     ├─ 가능하면 → lpAppend
     └─ 불가능하면 → 새 listpack 생성
```

encoding 변경, 전체 구조 재배치, ziplist 스타일의 연쇄 memmove는 발생하지 않습니다.

#### (7) 왜 stream은 이 구조를 선택했을까?

`streamAppendItem()` 코드는 Redis가 Stream을 설계할 때 내린 결론을 그대로 보여줍니다.
stream은 형태를 바꾸며 적응하는 구조가 아니라 처음부터 커질 것을 전제로 설계된 append 전용 로그 구조입니다.
따라서 redis는 stream에 대해 encoding 변환이라는 선택지를 애초부터 주지 않았죠.

append-only workload를 통해 기존 데이터는 건들지 않습니다.
Stream의 핵심 연산은 XADD인데 항상 맨 뒤에 추가하고 기존 entry는 수정되지 않죠.
이는 이전에 사용하던 ziplist와 달리 memmove와 같은 불필요한 비용을 줄였습니다.

또한 range scan 중심 패턴을 사용하여 구조 안정성을 더 중시합니다.
stream은 보통 id 범위 조회, 순차 소비를 수행합니다. 이 때 데이터가 연속적으로 정렬되어 있고
scan 중 구조가 바뀌지 않죠.

다시 말하면 scan 중 절대 형태가 바뀌지 않는 구조를 선택했다는 것입니다.
-> radix tree + listpack

ziplist는 연쇄적인 memmove로 성능 파악이 어려웠습니다.
하지만 listpack 단위 확장을 진행하는 stream은 이 패턴을 구조적으로 차단합니다.

```c
if (lp_bytes + totelelen >= node_max_bytes)
    new_node = 1;
```
listpack이 가득 차면 새 listpack을 생성할 뿐 기존 Listpack은 절대 이동하지 않습니다.
append 비용은 결과적으로 항상 O(1) ~ O(listpack 크기)입니다.
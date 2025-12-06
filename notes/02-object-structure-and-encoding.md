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

---
## 2-4 Encoding 자동 변환
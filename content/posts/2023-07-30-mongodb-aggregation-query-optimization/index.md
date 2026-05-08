---
title: "12초 걸리던 쿼리 장애를 처음 겪고, 끝까지 파고든 기록"
description: "MongoDB $lookup 병목 트러블슈팅"
date: 2023-07-30T18:43:15+09:00
# weight: 1
# aliases: ["/first"]
tags: ["tag"]
author: "Byeongmin Bae"
# author: ["Me", "You"] # multiple authors
draft: false
---

**회사의 지식재산권 보호를 위해 도메인과 스키마, 쿼리를 가상의 도서관 도메인으로 완전히 재구성하였고 실제 회사에서 쓰이는 것과는 관련이 없음을 밝힙니다.**

**이 글에서는 오직 문제 해결 과정만을 다룹니다.**

## 문제 정의

며칠 전 도서 검색 기능의 속도가 지나치게 느리다는 피드백을 받았습니다.

개발 환경에서는 성능 문제를 체감한 적이 없었고 사용 빈도도 높지 않았던 기능이라서, 솔직히 문제가 발생할 것이라고 예상하지 못했습니다

운영 환경에서 직접 재현해보니 검색어가 있을 때는 1초 미만이었지만, 없는 경우 약 12초의 지연이 발생했습니다.

이는 곧 **전체 도서를 보기 위해선 유저가 12초 동안 기다려야 한다**라는 말이 됩니다.

일반적으로 알려진 것처럼 5초 이상의 로딩은 사용자 이탈로 직결되는 만큼, 바로 원인 파악에 들어갔습니다.

## 기존 파이프라인 구조

```jsx
await Books.aggregate([ // Books 컬렉션에서 시작
    {
        // 특정 문자열을 가진 책을 1차로 필터링
        $match: {
            bookName: { $regex: new RegExp(`^${bookName}`, 'i') } 
        }
    },
    {
      	// 내려온 도큐먼트들에 대해 저자가 셰익스피어인 도서만 조인
        $lookup: {
            from: 'booksDetail',
            localField: '_id',
            foreignField: 'booksId',
            pipeline: [
                {
                    $match: {
                        authors: { $in: ['Shakespeare'] }
                    }
                }
            ],
            as: 'booksDetail'
        }
    },
    {
      	// $lookup 결과 배열 평탄화
        $unwind: { path: '$booksDetail' }
    },
    { 
        $project: {
            // 필요한 필드 추가 or 리네이밍 
        }
    },
    { $sort: { createdAt: -1 } } // 내림차순
]);
```

쿼리를 처음 작성했을 때는 "`bookName`에 인덱스가 있으니 1차 필터링은 빠를 거고, `$lookup` 내부에서 `author`까지 걸러주니 필요한 도큐먼트만 조인되겠지" 라고 생각했었습니다.

또한 개발 환경에선 충분히 빨랐던 탓에 검색어가 공백일때 어떤 문제가 발생하는지 크게 신경 쓰지 못했습니다.

이번에 피드백을 받고 바로 **개발과 운영간의 데이터 규모**를 비교해보았는데 직접적으로 말할순 없지만 **엄청난 차이**가 있었습니다.

현재 쿼리는 검색어가 공백이면 `^` 정규식이 컬렉션 전체를 훑습니다. n배 많은 데이터를 훑으면 그만큼 디스크에서 읽어야 하는 양도 늘어나니, **`$match` 단계의 도큐먼트 fetch 비용이 병목일 가능성이 높다**고 봤습니다.

다만 이건 어디까지나 추측이었습니다. 실제로 어느 스테이지에서 얼마나 많은 시간이 소요 되는지, 인덱스는 제대로 타고 있는지는 아직 확인하지 않은 상태였습니다. 

정확한 진단을 위해 explain을 뽑아봤습니다.

## explain 진단

설명은 주석에 포함했습니다. MongoDB의 explain은 트리 구조라 안쪽부터 읽으시면 됩니다. 

각 스테이지별 근사 소요 시간은 이전 스테이지와의 차이로 보시면 됩니다.

```javascript
{
    "stages" : [
        {
            "$cursor" : {
                "executionStats" : {
                    "nReturned" : 124638.0,
                    "executionTimeMillis" : 12921.0,
                    "totalKeysExamined" : 124638.0,
                    "totalDocsExamined" : 124638.0,
                    "executionStages" : {
                        "isCached" : false, // 여러번 실행해도 캐싱이 안됨
                        // 옵티마이저 최적화로 컬렉션쪽 필드에 한해 fetch 이후 바로 projection
                        "stage" : "PROJECTION_SIMPLE",
                        "executionTimeMillisEstimate" : 555.0,
                        "inputStage" : { 
                            "stage" : "FETCH", // WiredTiger 캐시 또는 디스크에서 가져옴
                            "executionTimeMillisEstimate" : 487.0,
                            "inputStage" : {
                                // 정규식에 의해 전체 도큐먼트가 선택되므로 사실상 풀스캔과 다를바가 없습니다.
                                "stage" : "IXSCAN", // 인덱스 스캔
                                "filter" : {
                                    "bookName" : { "$regex" : "^", "$options" : "i" }
                                },
                                "executionTimeMillisEstimate" : 232.0,
                                "indexName" : "bookName_1",
                                "direction" : "forward"
                            }
                        }
                    }
                }
            },
            "nReturned" : 124638,
            "executionTimeMillisEstimate" : 569
        },
        {
            "$lookup" : { },
            "totalDocsExamined" : 26,
            "totalKeysExamined" : 26,
            "collectionScans" : 0,
            "indexesUsed" : [
                "booksId_1_authors_1"
            ],
            "nReturned" : 26,
            "executionTimeMillisEstimate" : 12921 // 문제의 부분
        },
        {
            "$project" : { },
            "nReturned" : 26,
            "executionTimeMillisEstimate" : 12921
        },
        {
            "$sort" : { },
            "nReturned" : 26,
            "executionTimeMillisEstimate" : 12921
        }
    ],
}
```

explain 을 살펴보니 제 예상과는 달리 `$match`는 569ms로 생각보다 오래 소요되지 않았습니다. 

반대로, 시간을 제일 많이 소요하고 있는건 `$lookup`이었습니다.

그런데 수치를 보면 이상한 점이 있습니다. 

왜 `$lookup`의 `totalDocsExamined`는 26건이고 인덱스도 타고 있는데 **12,352ms** 나 소요되었을까요?

## explain 너머의 병목

```javascript
        {
            "$lookup" : { },
            "totalDocsExamined" : 26,
            "totalKeysExamined" : 26,
            "collectionScans" : 0,
            "indexesUsed" : [
                "booksId_1_authors_1"
            ],
            "nReturned" : 26,
            "executionTimeMillisEstimate" : 12921
        },
```

> "인덱스 레벨에서 26개를 정확히 선택했는데, 왜 여기서 오래 걸리는 거지?"

이 의문을 해소하기 위해 `$lookup` 내부 동작을 더 파고 들었습니다.

MongoDB 공식 GitHub 레포지토리에는 `$lookup` 스테이지의 explain에 관한 테스트 코드가 있는데, 주석을 자세히 읽어보면 힌트를 얻을 수 있습니다.

편의상 한글 번역을 했습니다.

```jsx
let testQueryExecutorStatsWithIndexScan = function() {
	createIndexForCollection(fromColl, "foreignField");

    let output = doAggregationLookup(localColl, fromColl, {allowDiskUse: false});

    let expectedOutput = [
        {_id: 0, localField: 0, output: [{_id: 0, foreignField: 0}]},
        {_id: 1, localField: 1, output: [{_id: 1, foreignField: 1}]}
    ];

    assert.eq(output, expectedOutput);

    let [curScannedObjects, curScannedKeys] = getCurrentQueryExecutorStats();

    // 인덱스 스캔의 경우, 총 scannedObjects는
    // (로컬 컬렉션의 전체 도큐먼트 수 + 외부 컬렉션에서 매칭된 도큐먼트 수)의 합이어야 한다
    assert.eq(localDocCount + localDocCount, curScannedObjects);

    // 외부 컬렉션에서 스캔된 키 수는 로컬 컬렉션의 도큐먼트 수와 동일해야 한다
    assert.eq(localDocCount, curScannedKeys);

    if (isSBELookupEnabled) {
        checkExplainOutputForAllVerbosityLevels(
            localColl,
            fromColl, 
            {
                // SBE lookup이 활성화된 경우, 실행 통계에서 모든 스캔 객체를 캡처할 수 있다
                // 따라서 totalDocsExamined는
                // (로컬 컬렉션의 전체 도큐먼트 수 + 외부 컬렉션에서 매칭된 도큐먼트 수)와 동일해야 한다
                totalDocsExamined: 2 + 2,
                // 로컬 컬렉션의 각 도큐먼트마다 인덱스 seek이 한번씩 수행되고,
                // seek당 키 하나가 검사된다 = 2
                totalKeysExamined: 2,
                // 로컬 컬렉션이 스캔된 횟수 = 1
                collectionScans: 1,
                // 인덱스 스캔 단계에서 검사된 키마다 외부 컬렉션에 대한 seek이 수행되어
                // 해당 도큐먼트를 가져온다 = 2
                collectionSeeks: 2,
                indexScans: 0,
                // 로컬 컬렉션의 각 도큐먼트마다 인덱스 seek이 한번씩 수행된다 = 2.
                indexSeeks: 2,
                indexesUsed: ["foreignField_1"]
			},
            {allowDiskUse: false},
            {strategy: "IndexedLoopJoin", indexName: "foreignField_1"});
    } else {
        checkExplainOutputForAllVerbosityLevels(localColl,
            fromColl, 
            {
                totalDocsExamined: 2,
                totalKeysExamined: 2,
                collectionScans: 0,
                indexesUsed: ["foreignField_1"]
            }, 
            {allowDiskUse: false}
        );
    }
};
```

`indexSeeks` 의 주석을 보면 **"로컬 컬렉션의 각 도큐먼트마다 인덱스 seek이 한번씩 수행된다"** 라고 명시되어있습니다.

즉, **`$match`에서 필터링되어 내려온 도큐먼트 각각에 대해 매칭 여부와 관계없이 foreign 컬렉션에 대한 seek 이 수행**됩니다. 인덱스가 존재하면 인덱스 seek으로, 없으면 풀 테이블 스캔으로 찾습니다.

인덱스는 빠르게 원본 데이터를 조회할 수 있도록 도와주지만 비용이 0은 아닙니다. 그중에는 B-Tree의 root에서 시작해 leaf 노드까지 내려가며 탐색하는 비용인 **seek 비용**이 있고, **조인 수행에 있어 이 seek 자체는 피할 수 없습니다**.

여기서 다시 explain 을 보면 퍼즐이 맞춰집니다. `$lookup` 으로 내려오는 도큐먼트는 124,638건 입니다. `$lookup` 에서 보이는 `"totalDocsExamined" : 26, "totalKeysExamined" : 26`은 최종 매칭 결과일 뿐이고 **실제로는 124,638건 각각에 대해 `booksId_1_authors_1` 인덱스에 seek이 발생**했다는 뜻입니다. 

결론적으로 보면 필요한 도큐먼트는 전체의 0.02%였고, 나머지 99.98%를 걸러내는 과정에서 **12만 번의 불필요한 seek 비용이 발생**했습니다. 이 비용이 누적되면서 `$lookup`에서만 12,352ms나 소요된 것입니다.

현재 쿼리는 SBE가 아닌 classic engine에서 실행되기 때문에 explain에서 `indexSeeks`를 직접 볼 수 없습니다. 직접 수치로 확인하고 싶어 로컬에서 유사한 환경을 구성해봤는데, 아쉽게도 `$lookup` 내부 pipeline 때문에 classic engine으로 fallback되어 `indexSeeks`를 직접 볼순 없었습니다.

그래도 구조상 seek이 124,638번 발생했다는 건 변하지 않습니다. 공식 문서에서 `$lookup` 앞단 도큐먼트를 줄이라고 권장하는 이유가 바로 여기에 있습니다.

## 파이프라인 재설계

이론적으로만 보면 **역정규화**를 고려해 볼 수 있지만, 현실적으로 해당 엔티티를 사용하는 모든 레거시 코드에 영향을 끼쳐 감당할 수 없기 때문에 변경이 **불가능** 합니다.

고민하다 보니 이런 흐름으로 생각이 이어졌습니다.

1. "Shakespeare" 저자가 포함된 도서는 도메인 특성상 극히 일부다.
    
2. `authors` 의 필터링은 `bookName` 의 값 유무와 관계없이 항상 필수다.
    
3. 그렇다면 선택적 조건인 `bookName` 필터를 **나중으로 미뤄도 최종 결과는 동일하지 않을까?**
    
4. 그리고 `authors` 를 먼저 필터링 하면 스코프가 훨씬 줄고 `$lookup` 에 전달되는 도큐먼트 수도 줄겠네?

핵심은 `$lookup`에 들어가는 도큐먼트 수를 최대한 줄이는 것입니다. 이를 바탕으로 전체 파이프라인을 재작성했습니다.

```jsx
await BooksDetail.aggregate([ // BooksDetail 에서 시작
    {
        // "Shakespeare" 저자를 가진 도서만 필터링(현재 26건)
        $match: {
            authors: { $in: ['Shakespeare'] }
        }
    },
    {
        // 앞서 필터링된 26건 각각에 대해서만 books 컬렉션과 조인
        $lookup: {
            from: 'books',
            localField: 'booksId',
            foreignField: '_id',
            pipeline: bookName ? [
                // 검색어가 있을 때만 정규식 필터를 추가
                {
                    $match: {
                        bookName: { $regex: new RegExp(`^${bookName}`, 'i') }
                    }
                }
            ] : [],
            as: 'books'
        }
    },
    {
        // $lookup 결과 배열 평탄화
        $unwind: { path: '$books' }
    },
    {
        $project: {
            // 필요한 필드 추가 or 리네이밍
        }
    },
    // 두 컬렉션간의 `createdAt` 은 앱 수준에서 동일한 시간을 보장
    { $sort: { createdAt: -1 } } // 내림차순
]);
```

지금까지 "도서 이름과 특정 저자를 가진" 이라는 **요구사항의 어순**에 이끌려 `books.bookName` 검색에만 집중해 왔습니다.

이번에는 시각을 바꿔 `booksDetail.authors` 기준으로 필터링을 먼저 수행하도록 스테이지를 재배치하였습니다.

## 옵티마이저의 선택

정렬 비용까지 낮춰보기 위해 `authors`, `createdAt` 순서로 복합인덱스를 생성하였습니다.

```jsx
db.booksDetail.createIndex({ authors: 1, createdAt: -1 });
```

`authors` 필터링 후 `createdAt` 기준으로 정렬된 상태를 그대로 읽을 수 있기 때문에, 이론적으로는 추가 정렬 비용을 줄일 수 있을 것으로 기대했습니다.

그런데 실제로는 옵티마이저가 이 인덱스를 선택하지 않고 기존의 `authors` 단일 인덱스를 사용했습니다.

### reject 된 이유

조인 이후 생성된 도큐먼트는 메모리에서 새롭게 조합된 BSON이기 때문에 원본 컬렉션의 인덱스를 그대로 활용할 수 없습니다.

즉, `$sort` 는 지금 만든 복합인덱스를 활용하지 못하고 인메모리 정렬을 수행하게 됩니다.

결과적으로 도움이 되지 않는 복합 인덱스를 유지할 이유가 없어 제거하였습니다.

`$sort` 에서 인메모리 정렬이 발생하긴 하지만, 현재 도메인 특성상 "Shakespeare" 저자가 포함된 도서수가 크게 늘어나지 않는다는 전제가 있어 이 정도 성능 저하는 수용 가능하다고 판단했습니다.

## 개선 결과

```jsx
{
    "stages" : [
        {
            "$cursor" : {
                "executionStats" : {
                    "nReturned" : 26.0,
                    "executionTimeMillis" : 2.0,
                    "totalKeysExamined" : 26.0,
                    "totalDocsExamined" : 26.0,
                    "executionStages" : {
                        "isCached" : true,
                        "stage" : "PROJECTION_SIMPLE",
                        "executionTimeMillisEstimate" : 0.0,
                        "inputStage" : {
                            "stage" : "FETCH",
                            "executionTimeMillisEstimate" : 0.0,
                            "inputStage" : {
                                "stage" : "IXSCAN",
                                "executionTimeMillisEstimate" : 0.0,
                                "indexName" : "authors_1",
                                "direction" : "forward",
                            }
                        }
                    }
                }
            },
            "nReturned" : 26,
            "executionTimeMillisEstimate" : 0
        },
        {
            "$lookup" : { },
            "totalDocsExamined" : 26,
            "totalKeysExamined" : 26,
            "collectionScans" : 0,
            "indexesUsed" : [
                "_id_"
            ],
            "nReturned" : 26,
            "executionTimeMillisEstimate" : 2
        },
        {
            "$project" : { },
            "nReturned" : 26,
            "executionTimeMillisEstimate" : 2
        },
        {
            "$sort" : { },
            "nReturned" : 26,
            "executionTimeMillisEstimate" : 2
        }
    ]
}
```

반복 실행해도 캐싱이 적용되지 않았던 개선 이전 쿼리와는 달리, **캐싱도 정상적으로 동작**합니다.

첫 번째 스테이지에서 `authors` 필터링으로 26건만 선택되어, 이전 쿼리의 124,638건과 비교했을 때 약 4,793배 적은 양의 데이터가 `$lookup`으로 내려옵니다.

| 항목 | 개선 전 | 개선 후 | 개선율 |
| --- | --- | --- | --- |
| 1차 필터링 후 결과량 | 124,638건 | 26건 | **99.98% 개선** |
| `$lookup` 수행 시간 | 12,352ms | 2ms | " |
| `$lookup` seek 비용 | 124,638 × log 124,638 | **26 × log 124,638** | " |
| 전체 수행 시간 | 12,921ms | 2~3ms | **평균 약 5,383배 개선** |
| 공백 검색에서 버려지는 연산 | 99.98% | 0% | 100% 제거 |

이제 검색어가 없는 최악의 경우에도 **4ms 이내**로 응답하게 되어, 장애 수준의 지연이 해결되었습니다.

## 회고

글에는 전부 담지 못했지만 이번 과정에서 배운 것들이 많습니다. 

사실 Aggregation 파이프라인을 깊게 다뤄본 경험이 거의 없어서, `$lookup`이 내부적으로 어떻게 동작하는지, 앞단 도큐먼트 수가 성능에 얼마나 큰 영향을 주는지 제대로 인식하지 못하고 있었습니다.

이번 일을 계기로, `$lookup`이 포함된 쿼리를 작성할 때는 개발 환경에서도 explain을 꼭 확인하는 습관을 들이려고 합니다. 인덱스가 제대로 타고 있는지, 각 스테이지에서 몇 건이 오가는지, 어디서 시간이 소요되는지를 미리 파악해두어야 운영 환경에서 문제가 되는 쿼리를 미리 걸러낼 수 있기 때문입니다.

저와 같은 문제를 겪는 분들께 도움이 되었으면 좋겠습니다.

읽어주셔서 감사합니다.

## 참고 자료

* MongoDB 깃허브 공식 테스트코드
    * https://github.com/mongodb/mongo/blob/v6.0/jstests/aggregation/sources/lookup/lookup_query_stats.js

* MongoDB 공식문서 - $lookup 성능 고려 사항
    * https://www.mongodb.com/docs/manual/reference/operator/aggregation/lookup/#performance-considerations
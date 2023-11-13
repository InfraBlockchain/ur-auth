## UR-Auth
**_UR-Auth_** 는 _Universal Resource Auth_ 의 약자로 URI(Uniform Resource Identifier)로 표현되는 웹 데이터 및 저작권이 있는 유무형 자산들에 대해 그 소유권을 블록체인 기술과 DID(Decentralized Identifiers) 기술을 이용하여 인터넷 상에 공개적으로 등록할 수 있도록 하는 프로토콜입니다. URI 는 온/오프라인 상의 논리적 물리적 리소스를 고유하게 식별할 수 있는 웹 기술에서 통용되는 식별자(Identifier)로써 블록체인에 해당 URI 의 소유자 DID 를 이용하여 그 소유권을 등록하게 되고 거대 AI 가 이를 학습할 때 정당하게 그 소유권을 주장할 수 있는 기술적인 방법을 마련할 수 있게 됩니다. 

## Data Ownership Register

데이터에 대한 소유권을 _UR-Auth_ 블록체인에 등록하는 타입은 크게 세가지로 나눕니다.

- **도메인**: `https://www.bc-labs.net` 고 같은 일반적인 도메인을 의미합니다.
- **웹 서비스 계정**: `https://instagram.com/user` 과 같이 어떤 서비스에 대한 계정을 의미합니다.
- **데이터 파일의 저작권**: 로컬 데이터에 대한 소유권을 의미합니다. 여기서는 ipfs 와 같이 분산형 저장소의 주소값(e.g CID) 이 들어갈 수 있습니다.
- **데이터셋**: `URAuthTree` 에 등록된 URI 혹은 등록되지 않은 URI 를 이용하여 만든 데이터셋에 대한 소유권을 의미합니다. 해당 데이터셋이 저장되어있는 저장소에 대한 위치값이 들어갈 수 있습니다.

각 영역별 소유권을 등록하는 방법은 다음과 같습니다:

### 도메인

1. 도메인 소유자는 자신의 DID를 생성하고 **_UR-Auth_** 블록체인에 `request_register_ownership` 트랜잭션을 전송합니다.

2. **_UR-Auth_** 블록체인에서 챌린지 값을 생성합니다.

3. 도메인 소유자는 도메인 검증 정보를 담고 있는 _*.json_ 파일을 생성한 후 해당 도메인의 `root` 디렉토리에 업로드합니다. 
예를 들면, `bc-labs.net/root` 에 `challenge.json` 파일을 업로드합니다.

4. 신뢰할 수 있는 노드로 구성된 오라클 노드들은 해당 _*.json_ 파일을 다운로드 후 **_UR-Auth_** 블록체인에 `verify_challenge` 트랜잭션을 전송합니다. 

5. 정족수 이상의 오라클 노드(e.g 60% 이상)에 의해 검증이 완료되면 해당 도메인은 **_[UR-Auth Tree]()_** 에 등록이 되고 소유권 등록이 완료됩니다.

### 웹 서비스 계정

OAuth 인증을 통하여 계정에 대한 소유권을 인증할 수 있는 경우:

- `claim_ownership` 트랜잭션을 전송하여 해당 URI 를 `UR-Auth Tree` 에 등록합니다.

OAuth 인증이 불가능한 경우:

1. 유저는 자신의 피드에 계정에 대한 소유권을 증명할 수 있는 증명서를 포스팅합니다. 

2. 신뢰할 수 있는 노드로 구성된 오라클 노드들에 의해 위와 같이 검증 절차를 거칩니다.

3. 정족수 이상의 오라클 노드에 의한 검증이 완료되면 `UR-Auth Tree`
 에 등록합니다.

### 데이터 파일에 대한 저작권 및 데이터셋

1. 파일 및 데이터셋을 등록하게 되면 `urauth://file/{cid}` 혹은 `urauth://dataset/{cid}` URI 를 발급받게 됩니다.

2. 해당 URI 를 `UR-Auth Tree` 에 등록하게 됩니다.

## UR-Auth Tree

웹사이트 URL 및 웹사이트 내 하위 페이지 URL들은 블록체인 상에서 Tree 데이터 구조의 각 노드들로 표현될 수 있습니다. 하나의 **_UR-Auth Tree_** 는 하나의 웹사이트 도메인과 해당 도메인 내 URI로 식별되는 데이터들에 대응하며, **_UR-Auth Tree_** 의 각 노드는 해당 URI의 소유권자(DID) 정보, 저작권정보, 데이터 접근 규칙 등이 규정된 **_UR-Auth Document_** 를 저장하고 있습니다. 

### UR-Auth Tree 등록 규칙

1. **_UR-Auth Tree_** 의 모든 하위 노드의 등록은 오라클에 의한 검증이 아니라면 그 상위 노드의 소유자 중 한 소유자에 의해 등록되어야 합니다.

2. `http:` 혹은 `https:` 은 같은 것으로 간주되며 생략되어 등록되어야 하며 그 이외의 프로토콜은 명시되어 등록되어야 합니다.

3. `www` 는 생략되어 등록되며 그 이외의 접두사는 명시되어 등록되어야 합니다.

4. 루트 노드는 오라클에 의해 검증된 후 등록되어야 합니다.

## Universal Resource Auth (UR-Auth) Document

**_UR-Auth Tree_** 의 각 노드는 해당 URI와 모든 하위 URI들에 적용되는 소유권 정보, 저작권 정보, 데이터 접근 규칙 등의 정보가 기록된 **_UR-Auth Document_**를 갖습니다. **_UR-Auth Document_** 는 해당 노드의 소유자 DID에 의해서만 내용이 수정될 수 있습니다.

```rust
#[derive(Encode, Decode, Clone, PartialEq, Debug, Eq, TypeInfo)]
pub struct URAuthDoc<Account> {
    pub id: DocId,
    pub created_at: u128,
    pub updated_at: u128,
    pub multi_owner_did: MultiDID<Account>,
    pub identity_info: Option<Vec<IdentityInfo>>,
    pub content_metadata: Option<ContentMetadata>,
    pub copyright_info: Option<CopyrightInfo>,
    pub access_rules: Option<Vec<AccessRule>>,
    pub asset: Option<MultiAsset>,
    pub data_source: Option<URI>,
    pub proofs: Option<Vec<Proof>>,
}
```

### id
해당 문서의 식별자

### created_at
해당 문서가 생성된 시간

### updated_at
해당 문서가 업데이트된 시간

### multi_owner_did
해당 문서의 소유자 DID 목록

### identity_info
저작권자의 신원 정보 목록

### contents_metadta
해당 URI 와 연관된 컨텐츠 메타 데이터 정보

### access_rules
해당 URI 에 대한 접근 규칙 목록

### asset
해당 문서가 데이터셋일 경우, 토큰화된 데이터셋에 대한 정보

### data_source
해당 문서가 데이터셋일 경우, 데이터셋이 저장되어 있는 URI 정보

### proofs
해당 문서에 대한 전자서명 목록 

## Data Market

**_UR-Auth_** 블록체인 상에 미리 패키징된 웹 Dataset들도 함께 Data Market 에 등록되고 거래 유통되도록 하여, 웹 데이터 수요자들이 웹 데이터 소유자들에게 정당한 데이터 접근 비용을 지불하고 미리 정리된 데이터셋들을 다운로드 받아서 상업용 AI 기계학습 등에 사용하도록 하여 데이터 저작권 문제를 해결할 수 있습니다. 

### Tokenized of Dataset and AI Model

**_URAuth_** 블록체인에는 데이터에 대한 소유권이 명시되어 있기 때문에 해당 URI 로 만들어진 데이터셋 혹은 AI Model 에 대한 지분을 토큰화 할 수 있습니다. 실제로 Data Market 에서 해당 데이터셋이 판매가 되었을 때 토큰화된 지분에 따라 보상을 분배할 수 있습니다. 

## References

- [URAuth White Paper]()
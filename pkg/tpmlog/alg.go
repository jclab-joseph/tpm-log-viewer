package tpmlog

import (
	"crypto"
	_ "crypto/sha1" // 리플레이용 해시 등록
	_ "crypto/sha256"
	_ "crypto/sha512"
	"fmt"
)

// AlgorithmID 는 TPM_ALG_ID (TCG Algorithm Registry) 값이다.
type AlgorithmID uint16

const (
	AlgSHA1     AlgorithmID = 0x0004
	AlgSHA256   AlgorithmID = 0x000B
	AlgSHA384   AlgorithmID = 0x000C
	AlgSHA512   AlgorithmID = 0x000D
	AlgSM3_256  AlgorithmID = 0x0012
	AlgSHA3_256 AlgorithmID = 0x0027
	AlgSHA3_384 AlgorithmID = 0x0028
	AlgSHA3_512 AlgorithmID = 0x0029
)

var algNames = map[AlgorithmID]string{
	AlgSHA1:     "sha1",
	AlgSHA256:   "sha256",
	AlgSHA384:   "sha384",
	AlgSHA512:   "sha512",
	AlgSM3_256:  "sm3-256",
	AlgSHA3_256: "sha3-256",
	AlgSHA3_384: "sha3-384",
	AlgSHA3_512: "sha3-512",
}

// 스펙 헤더(TCG_EfiSpecIdEvent)에 크기가 없을 때 사용하는 기본 다이제스트 길이.
var algSizes = map[AlgorithmID]int{
	AlgSHA1:     20,
	AlgSHA256:   32,
	AlgSHA384:   48,
	AlgSHA512:   64,
	AlgSM3_256:  32,
	AlgSHA3_256: 32,
	AlgSHA3_384: 48,
	AlgSHA3_512: 64,
}

// 리플레이(PCR 재계산)에 사용할 수 있는 해시.
var algHashes = map[AlgorithmID]crypto.Hash{
	AlgSHA1:   crypto.SHA1,
	AlgSHA256: crypto.SHA256,
	AlgSHA384: crypto.SHA384,
	AlgSHA512: crypto.SHA512,
}

func (a AlgorithmID) String() string {
	if n, ok := algNames[a]; ok {
		return n
	}
	return fmt.Sprintf("alg(0x%04X)", uint16(a))
}

// Size 는 알고리즘의 표준 다이제스트 길이를 반환한다. 미지의 알고리즘이면 0.
func (a AlgorithmID) Size() int { return algSizes[a] }

// Hash 는 PCR 리플레이에 쓸 해시를 반환한다. 지원하지 않으면 ok=false.
func (a AlgorithmID) Hash() (crypto.Hash, bool) {
	h, ok := algHashes[a]
	if !ok || !h.Available() {
		return 0, false
	}
	return h, true
}

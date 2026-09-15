package tpmlog

import (
	"fmt"
	"sort"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

// PCRBank 는 실제 TPM 에서 읽은 하나의 알고리즘 뱅크(PCR 전체)다.
type PCRBank struct {
	Alg    AlgorithmID
	Values []PCRValue
}

// 한 번의 TPM2_PCR_Read 로 요청할 PCR 개수. TPM 은 응답 버퍼 크기에 따라
// 요청보다 적게 돌려줄 수 있어서 어차피 여러 번 나눠 읽는다.
const pcrReadChunk = 8

// ReadTPMPCRs 는 로컬 TPM 2.0 에서 할당된 모든 뱅크의 현재 PCR 값을 읽는다.
// TPM 이 없거나 접근 권한이 없으면 오류를 반환한다.
func ReadTPMPCRs() ([]PCRBank, error) {
	tpm, err := openTPM()
	if err != nil {
		return nil, err
	}
	defer tpm.Close()
	return readPCRBanks(tpm)
}

// readPCRBanks 는 TPM2_GetCapability(TPM_CAP_PCRS) 로 할당된 뱅크를 알아낸 뒤
// 각 뱅크를 읽는다.
func readPCRBanks(tpm transport.TPM) ([]PCRBank, error) {
	cap, err := tpm2.GetCapability{
		Capability:    tpm2.TPMCapPCRs,
		Property:      0,
		PropertyCount: 32,
	}.Execute(tpm)
	if err != nil {
		return nil, fmt.Errorf("TPM2_GetCapability(PCRS): %w", err)
	}
	assigned, err := cap.CapabilityData.Data.AssignedPCR()
	if err != nil {
		return nil, fmt.Errorf("TPM2_GetCapability(PCRS): %w", err)
	}

	var banks []PCRBank
	for _, sel := range assigned.PCRSelections {
		pcrs := selectedPCRs(sel.PCRSelect)
		if len(pcrs) == 0 {
			continue // 할당되지 않은 뱅크
		}
		values, err := readBank(tpm, sel.Hash, pcrs)
		if err != nil {
			return banks, err
		}
		banks = append(banks, PCRBank{Alg: AlgorithmID(sel.Hash), Values: values})
	}
	return banks, nil
}

// readBank 은 한 알고리즘 뱅크의 PCR 들을 나눠 읽는다.
func readBank(tpm transport.TPM, alg tpm2.TPMIAlgHash, pcrs []uint32) ([]PCRValue, error) {
	var out []PCRValue
	for len(pcrs) > 0 {
		n := min(len(pcrs), pcrReadChunk)
		rsp, err := tpm2.PCRRead{
			PCRSelectionIn: tpm2.TPMLPCRSelection{
				PCRSelections: []tpm2.TPMSPCRSelection{{
					Hash:      alg,
					PCRSelect: pcrBitmap(pcrs[:n]),
				}},
			},
		}.Execute(tpm)
		if err != nil {
			return out, fmt.Errorf("TPM2_PCR_Read(%s): %w", AlgorithmID(alg), err)
		}

		// 응답의 selection 은 TPM 이 실제로 돌려준 PCR 들이다. 다이제스트는
		// PCR 번호 오름차순으로 같은 개수만큼 들어 있다.
		var got []uint32
		for _, sel := range rsp.PCRSelectionOut.PCRSelections {
			if sel.Hash != alg {
				continue
			}
			got = append(got, selectedPCRs(sel.PCRSelect)...)
		}
		sort.Slice(got, func(i, j int) bool { return got[i] < got[j] })
		if len(got) == 0 || len(rsp.PCRValues.Digests) == 0 {
			// 더 진행해도 같은 응답만 나온다.
			return out, fmt.Errorf("TPM2_PCR_Read(%s): TPM returned no PCR values", AlgorithmID(alg))
		}

		read := map[uint32]bool{}
		for i, idx := range got {
			if i >= len(rsp.PCRValues.Digests) {
				break
			}
			out = append(out, PCRValue{
				PCRIndex: idx,
				Alg:      AlgorithmID(alg),
				Value:    rsp.PCRValues.Digests[i].Buffer,
			})
			read[idx] = true
		}

		rest := make([]uint32, 0, len(pcrs))
		for _, p := range pcrs {
			if !read[p] {
				rest = append(rest, p)
			}
		}
		if len(rest) == len(pcrs) {
			return out, fmt.Errorf("TPM2_PCR_Read(%s): no progress reading PCRs", AlgorithmID(alg))
		}
		pcrs = rest
	}
	sort.Slice(out, func(i, j int) bool { return out[i].PCRIndex < out[j].PCRIndex })
	return out, nil
}

// selectedPCRs 는 TPMS_PCR_SELECTION 의 비트맵을 PCR 번호 목록으로 바꾼다.
func selectedPCRs(bitmap []byte) []uint32 {
	var out []uint32
	for i, b := range bitmap {
		for bit := 0; bit < 8; bit++ {
			if b&(1<<bit) != 0 {
				out = append(out, uint32(i*8+bit))
			}
		}
	}
	return out
}

// pcrBitmap 은 PCR 번호 목록을 TPMS_PCR_SELECTION 비트맵으로 바꾼다.
func pcrBitmap(pcrs []uint32) []byte {
	size := 3 // TPM 2.0 최소 PCR 뱅크 크기(24 PCR)
	for _, p := range pcrs {
		if n := int(p/8) + 1; n > size {
			size = n
		}
	}
	bitmap := make([]byte, size)
	for _, p := range pcrs {
		bitmap[p/8] |= 1 << (p % 8)
	}
	return bitmap
}

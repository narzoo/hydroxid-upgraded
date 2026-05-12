package protonmail

import "testing"

func TestAPIErrorGetHVDetails(t *testing.T) {
	apiErr := &APIError{
		Code: HumanVerificationRequired,
		Details: []byte(`{
			"HumanVerificationMethods":["captcha"],
			"HumanVerificationToken":"token-123"
		}`),
	}

	hv, err := apiErr.GetHVDetails()
	if err != nil {
		t.Fatalf("GetHVDetails() error = %v", err)
	}
	if hv.Token != "token-123" {
		t.Fatalf("GetHVDetails().Token = %q", hv.Token)
	}
	if len(hv.Methods) != 1 || hv.Methods[0] != "captcha" {
		t.Fatalf("GetHVDetails().Methods = %#v", hv.Methods)
	}
}

func TestAPIHVDetailsVerifyURLAndSolvedCopy(t *testing.T) {
	hv := &APIHVDetails{
		Methods: []string{"captcha"},
		Token:   "seed-token",
	}

	if got := hv.VerifyURL(); got != "https://verify.proton.me/?methods=captcha&token=seed-token" {
		t.Fatalf("VerifyURL() = %q", got)
	}

	solved := hv.SolvedCopy("composite-token")
	if solved.Token != "composite-token" {
		t.Fatalf("SolvedCopy().Token = %q", solved.Token)
	}
	if len(solved.Methods) != 1 || solved.Methods[0] != "captcha" {
		t.Fatalf("SolvedCopy().Methods = %#v", solved.Methods)
	}
	if hv.Token != "seed-token" {
		t.Fatalf("SolvedCopy mutated original token = %q", hv.Token)
	}
}

package protonmail

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
)

const (
	HumanVerificationRequired   = 9001
	HumanValidationInvalidToken = 12087
)

var ErrAPIErrIsNotHVErr = errors.New("not human verification error")

type APIHVDetails struct {
	Methods []string `json:"HumanVerificationMethods"`
	Token   string   `json:"HumanVerificationToken"`
}

func (err *APIError) IsHVError() bool {
	return err != nil && err.Code == HumanVerificationRequired
}

func (err *APIError) GetHVDetails() (*APIHVDetails, error) {
	if !err.IsHVError() {
		return nil, ErrAPIErrIsNotHVErr
	}

	details := new(APIHVDetails)
	if len(err.Details) == 0 {
		return nil, fmt.Errorf("human verification details missing from API error")
	}
	if err := json.Unmarshal(err.Details, details); err != nil {
		return nil, err
	}
	if details.Token == "" {
		return nil, fmt.Errorf("human verification token missing from API error details")
	}
	return details, nil
}

func (hv *APIHVDetails) VerifyURL() string {
	if hv == nil || hv.Token == "" {
		return ""
	}

	values := url.Values{}
	if len(hv.Methods) > 0 {
		values.Set("methods", strings.Join(hv.Methods, ","))
	}
	values.Set("token", hv.Token)
	return "https://verify.proton.me/?" + values.Encode()
}

func (hv *APIHVDetails) SolvedCopy(solvedToken string) *APIHVDetails {
	if hv == nil {
		return nil
	}

	methods := append([]string(nil), hv.Methods...)
	return &APIHVDetails{
		Methods: methods,
		Token:   solvedToken,
	}
}

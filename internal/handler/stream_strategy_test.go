package handler

import "testing"

func TestIsNonStrategyFailureTimeout(t *testing.T) {
	if !isNonStrategyFailure("timeout") {
		t.Fatalf("expected timeout to be non-strategy failure")
	}
	if isNonStrategyFailure("html_response") {
		t.Fatalf("expected html_response to be strategy failure")
	}
}

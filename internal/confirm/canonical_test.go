package confirm_test

import (
	"testing"

	"github.com/saadbutt/toolgate/internal/confirm"
	"github.com/saadbutt/toolgate/internal/tools"
)

// TestCanonicalHashesAreStable pins the exact hashes this implementation
// produces.
//
// Two reasons these are hardcoded rather than computed. First, the
// confirmation check is only meaningful if the encoding never drifts: a
// change here would silently invalidate every stored intent. Second, the
// TypeScript port in typescript/ asserts the same values, so these fixtures
// are what keep the two implementations honest about each other.
func TestCanonicalHashesAreStable(t *testing.T) {
	cases := []struct {
		name string
		args tools.Args
		want string
	}{
		{
			name: "typical refund",
			args: tools.Args{"invoice_id": "INV-1002", "amount_cents": int64(4200), "reason": "duplicate charge"},
			want: "a8c23bbb2d44e3752e9390e4dfdd45e22985e0893b77c6d57275f96ed4fd5cf6",
		},
		{
			name: "key order must not matter",
			args: tools.Args{"z": "last", "a": "first", "m": int64(5)},
			want: "39a0ebe20e535c8de316cc4c3b67ed0af35b8a179f1bba5d35685fe6e0815b20",
		},
		{
			// Go's encoder escapes <, > and & by default. Any port has to
			// match that or the hashes diverge on ordinary text.
			name: "html-escaped characters",
			args: tools.Args{"note": "a<b && c>d", "n": int64(1)},
			want: "52e75a7c673c4be58a0dd6683045abdf3ffe300544c374ac683e178da1a0fe46",
		},
		{
			name: "booleans and empty strings",
			args: tools.Args{"flag": true, "empty": ""},
			want: "d726b9c4e59b06b8918a6d61ed472b5cef8bb797aaa99c3d3b4d8dc428b7f852",
		},
		{
			// Go's encoder also escapes U+2028 and U+2029, which JSON.stringify
			// emits raw. Text pasted from a PDF or a web page carries them.
			name: "line and paragraph separators",
			args: tools.Args{"reason": "pasted\u2028from a pdf\u2029end", "n": int64(1)},
			want: "3720098229543bfb785c62aee8e0f39dff64a38cb9d60e083a875475051bc38a",
		},
		{
			// Everything else outside ASCII is written as raw UTF-8 on both sides.
			name: "non-ascii text",
			args: tools.Args{"customer": "Café Zürich", "note": "☕ 日本 😀"},
			want: "4553c0ec725a4436946d0b375aa8d4c2a4a23d899db6a0b142add410b79db150",
		},
		{
			// Short escapes for \b and \f, \u00XX for the rest. Go before 1.22
			// wrote \u0008 and \u000c, so this pins the encoder version too.
			name: "control characters",
			args: tools.Args{"note": "tab\tline\nreturn\rback\bfeed\fnul\u0000unit\u001f"},
			want: "e7c038839695a31799b03ef8f5e11b6a4cf477d26875e34a21ea9255ebef9a7c",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := confirm.HashArgs(tc.args)
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.want {
				t.Fatalf("canonical encoding changed\n got  %s\n want %s", got, tc.want)
			}
		})
	}
}

package fwmark

import "testing"

func TestFromMarkUsesHigh32Bits(t *testing.T) {
	mark := uint64(0x12345678abcdef01)

	if got := FromMark(mark); got != 0x12345678 {
		t.Fatalf("FromMark(%#x) = %#x, want 0x12345678", mark, got)
	}
}

func TestToMark(t *testing.T) {
	fwmark := uint32(0x12345678)

	// ToMark should shift the 32-bit value into the higher 32 bits,
	// leaving the lower 32 bits as 0.
	if got := ToMark(fwmark); got != 0x1234567800000000 {
		t.Fatalf("ToMark(%#x) = %#x, want 0x1234567800000000", fwmark, got)
	}
}

func TestRoundtrip(t *testing.T) {
	originalFwmark := uint32(0xdeadbeef)

	// 1. ToMark: uint32 -> uint64
	mark := ToMark(originalFwmark)

	// 2. FromMark: uint64 -> uint32
	recoveredFwmark := FromMark(mark)
	if recoveredFwmark != originalFwmark {
		t.Fatalf("FromMark(ToMark(%#x)) = %#x, want %#x", originalFwmark, recoveredFwmark, originalFwmark)
	}

	// 3. ToMark: uint32 -> uint64 (Completing the requested loop)
	finalMark := ToMark(recoveredFwmark)
	if finalMark != mark {
		t.Fatalf("ToMark(FromMark(%#x)) = %#x, want %#x", mark, finalMark, mark)
	}
}

func TestFormat(t *testing.T) {
	if got := Format(0x1234); got != "0x00001234" {
		t.Fatalf("Format() = %q, want 0x00001234", got)
	}
}

func TestParse(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    uint32
		wantErr bool
	}{
		{"without 0x", "1234abcd", 0x1234abcd, false},
		{"with 0x", "0x1234abcd", 0x1234abcd, false},
		{"lowercase", "0xdeadbeef", 0xdeadbeef, false},
		{"uppercase", "0xDEADBEEF", 0xdeadbeef, false},
		{"leading spaces", "  0x1a2b", 0x1a2b, false},
		{"trailing spaces", "0x1a2b  ", 0x1a2b, false},
		{"mixed spaces", " 0x1a2b ", 0x1a2b, false},
		{"zero", "0x0", 0, false},
		{"zero without prefix", "0", 0, false},
		{"max uint32", "0xffffffff", 0xffffffff, false},
		{"invalid hex", "0xzzzz", 0, true},
		{"too long", "0x123456789", 0, true}, // > 32 bits
		{"empty string", "", 0, true},
		{"only prefix", "0x", 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Parse(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("Parse(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("Parse(%q) = %#x, want %#x", tt.input, got, tt.want)
			}
		})
	}
}

func TestRoundtripFormatParse(t *testing.T) {
	testValues := []uint32{
		0,
		0x1234,
		0xdeadbeef,
		0xffffffff,
		0x0abcdef0,
	}

	for _, original := range testValues {
		formatted := Format(original)
		parsed, err := Parse(formatted)
		if err != nil {
			t.Fatalf("Parse(%q) returned error: %v", formatted, err)
		}
		if parsed != original {
			t.Errorf("Roundtrip failed: Format(%#x) = %q, Parse(%q) = %#x", original, formatted, formatted, parsed)
		}
		// Second Format after Parse should equal original Format
		if got := Format(parsed); got != formatted {
			t.Errorf("Double format mismatch: Format(Parse(Format(%#x))) = %q, want %q", original, got, formatted)
		}
	}
}

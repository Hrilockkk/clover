package obfuscate

// Decrypt restores a plaintext string from an obfuscated byte slice produced by
// the cmd/genobf generator. The first byte is the random salt; the rest is the
// ciphertext. Each byte is XORed with a position- and round-dependent key.
func Decrypt(data []byte) string {
	if len(data) < 2 {
		return ""
	}
	salt := data[0]
	n := len(data) - 1
	out := make([]byte, n)
	rounds := 5 + int(salt)%5
	for i := 0; i < n; i++ {
		out[i] = data[i+1] ^ key(salt, i, rounds)
	}
	return string(out)
}

func key(salt byte, pos, rounds int) byte {
	k := salt
	for r := 0; r < rounds; r++ {
		k = (k*9 + 17) ^ byte(pos) ^ byte(r)
	}
	return k
}

// Must is a convenience wrapper that panics on invalid input. It should only be
// used for generated constants that are guaranteed to be well-formed.
func Must(data []byte) string {
	if len(data) < 2 {
		panic("obfuscate: empty data")
	}
	return Decrypt(data)
}

// O contains the generated obfuscated byte slices. It is populated by the
// cmd/genobf generator into z_obfuscated.go.
var O = map[string][]byte{}

// S decrypts an entry from O by name. Used as a fallback for dynamic lookups.
func S(name string) string {
	return Decrypt(O[name])
}

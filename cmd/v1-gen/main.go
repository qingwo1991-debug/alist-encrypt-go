// Test helper: creates V1-encrypted files for testing auto-detection.
package main

import (
	"fmt"
	"io"
	"os"

	"github.com/alist-encrypt-go/internal/encryption"
)

func main() {
	if len(os.Args) < 5 {
		fmt.Fprintf(os.Stderr, "Usage: v1-gen <password> <encType> <input> <output>\n")
		os.Exit(1)
	}
	password := os.Args[1]
	encType := os.Args[2]
	input := os.Args[3]
	output := os.Args[4]

	info, err := os.Stat(input)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	in, err := os.Open(input)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	defer in.Close()

	out, err := os.Create(output)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	defer out.Close()

	cipher, err := encryption.NewCipher(encryption.EncType(encType), password, info.Size())
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	reader := cipher.EncryptReader(in)
	n, err := io.Copy(out, reader)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("V1 encrypted: %s (%d bytes, encType=%s)\n", output, n, encType)
}

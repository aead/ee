package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"os"

	"github.com/minio/sio"

	"golang.org/x/crypto/scrypt"
)

func verifyArgs(encrypt, decrypt, keyGen, src, dst string) (ok bool) {
	if encrypt != "" && decrypt != "" {
		fmt.Fprintln(os.Stderr,"Cannot use -enc and -dec option at the same time")
		return
	}
	if encrypt != "" && keyGen != "" {
		fmt.Fprintln(os.Stderr,"Cannot use -enc and -gen option at the same time")
		return
	}
	if decrypt != "" && keyGen != "" {
		fmt.Fprintln(os.Stderr,"Cannot use -dec and -gen option at the same time")
		return
	}
	if keyGen != "" && (src != "" || dst != "") {
		fmt.Fprintln(os.Stderr,"Cannot use -gen with source and/or destination")
		return
	}
	return true
}

func examples() {
	fmt.Println("")
	fmt.Println("Examples of ee:")
	fmt.Println("")
	fmt.Println("   Derive and print encryption key: ee -gen your-password -iv your-iv")
	fmt.Println("   Encrypt and print file         : ee -enc your-password -iv your-iv -src /path/to/your/file")
	fmt.Println("   Encrypted file copy            : ee -enc your-password -iv your-iv -src /path/to/your/src -dst /path/to/your/dst")
	fmt.Println("   Decrypted file copy with pipes : cat /path/to/your/src | ee -dec your-password -iv your-iv > /path/to/your/dst")
}

func main() {
	encrypt := flag.String("enc", "", "Encrypt data with the provided password")
	decrypt := flag.String("dec", "", "Decrypt data with the provided password")
	iv := flag.String("iv", "", "The IV used to derive a key from the password")
	keyGen := flag.String("gen", "", "Generate and print the derived key from the provided password")
	src := flag.String("src", "", "The source file ee will try to read from - default is STDIN")
	dst := flag.String("dst", "", "The destination file ee will try to write to - default is STDOUT")

	flag.Parse()
	if len(os.Args) < 2 {
		flag.Usage()
		examples()
		return
	}
	if !verifyArgs(*encrypt, *decrypt, *keyGen, *src, *dst) {
		return
	}
	if flag.NArg() > 1 {
		flag.Usage()
		examples()
		return
	}

	var err error
	in, out := os.Stdin, os.Stdout
	if *src != "" {
		in, err = os.Open(*src)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to open file '%s': %v", *src, err)
			fmt.Fprintln(os.Stderr)
			return
		}
	}
	if *dst != "" {
		out, err = os.Open(*dst)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to create file '%s': %v", *dst, err)
			fmt.Fprintln(os.Stderr)
			return
		}
	}

	password := *encrypt
	if *encrypt == "" {
		password = *decrypt
	}

	key, err := scrypt.Key([]byte(password), []byte(*iv), 32768, 8, 1, 32)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to derive encryption key: %v", err)
		fmt.Fprintln(os.Stderr)
		return
	}

	if *keyGen != "" {
		fmt.Println(hex.EncodeToString(key))
		return
	}

	if *encrypt != "" {
		_, err = sio.Encrypt(out, in, sio.Config{Key: key})
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to encrypt data: %v", err)
			fmt.Fprintln(os.Stderr)
			return
		}
	} else {
		_, err = sio.Decrypt(out, in, sio.Config{Key: key})
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to decrypt data: %v", err)
			fmt.Fprintln(os.Stderr)
			return
		}
	}
}

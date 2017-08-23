package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"os"

	"github.com/minio/aead"
	"golang.org/x/crypto/scrypt"
)

func printUsage() {
	fmt.Println("Usage of ee:")
	fmt.Println("   enc")
	fmt.Println("      Encrypt data - see help: ee enc -h")
	fmt.Println("   dec")
	fmt.Println("      Decrypt data - see help: ee dec -h")
}

func main() {
	if len(os.Args) < 3 {
		printUsage()
		return
	}

	switch os.Args[1] {
	default:
		printUsage()
		return
	case "enc":
		enc := flag.NewFlagSet("enc", flag.ExitOnError)
		pwd := enc.String("pwd", "", "The password used derive a encryption key and encrypt the data")
		salt := enc.String("salt", "", "The salt used to derive an encryption key from the password")
		key := enc.String("key", "", "The encryption key used to encrypt data - cannot be used with a password and must be 256 bit key as HEX")
		if err := enc.Parse(os.Args[2:]); err != nil {
			fmt.Println(err)
			return
		}
		encrypt(*pwd, *salt, *key)
	case "dec":
		dec := flag.NewFlagSet("dec", flag.ExitOnError)
		pwd := dec.String("pwd", "", "The password used derive a encryption key and encrypt the data")
		salt := dec.String("salt", "", "The salt used to derive an encryption key from the password")
		key := dec.String("key", "", "The encryption key used to encrypt data - cannot be used with a password and must be 256 bit key as HEX")
		if err := dec.Parse(os.Args[2:]); err != nil {
			fmt.Println(err)
			return
		}
		decrypt(*pwd, *salt, *key)
	}
}

func encrypt(pwd, salt, key string) {
	if pwd != "" && key != "" {
		fmt.Println("Cannot use password and encryption key")
		return
	}
	if key != "" {
		encKey, err := hex.DecodeString(key)
		if err != nil {
			fmt.Println("Failed to parse encryption key - Is the key not a HEX value?")
			return
		}
		if _, err = aead.Encrypt(os.Stdout, os.Stdin, aead.Config{Key: encKey}); err != nil {
			fmt.Println("Failed to encrypt data: ", err)
			return
		}
	}
	if pwd != "" {
		key, err := scrypt.Key([]byte(pwd), []byte(salt), 16384, 8, 1, 32)
		if err != nil {
			fmt.Println("Failed to derive encryption key from password and salt: ", err)
			return
		}
		if _, err = aead.Encrypt(os.Stdout, os.Stdin, aead.Config{Key: key}); err != nil {
			fmt.Println("Failed to encrypt data: ", err)
			return
		}
	}
	if pwd == "" {
		fmt.Println("Missing password and salt")
		return
	}
}

func decrypt(pwd, salt, key string) {
	if pwd != "" && key != "" {
		fmt.Println("Cannot use password and decryption key")
		return
	}
	if key != "" {
		encKey, err := hex.DecodeString(key)
		if err != nil {
			fmt.Println("Failed to parse decryption key - Is the key not a HEX value?")
			return
		}
		if _, err = aead.Decrypt(os.Stdout, os.Stdin, aead.Config{Key: encKey}); err != nil {
			fmt.Println("Failed to decrypt data: ", err)
			return
		}
	}
	if pwd != "" {
		key, err := scrypt.Key([]byte(pwd), []byte(salt), 16384, 8, 1, 32)
		if err != nil {
			fmt.Println("Failed to derive decryption key from password and salt: ", err)
			return
		}
		if _, err = aead.Decrypt(os.Stdout, os.Stdin, aead.Config{Key: key}); err != nil {
			fmt.Println("Failed to decrypt data: ", err)
			return
		}
	}
	if pwd == "" {
		fmt.Println("Missing password and salt")
		return
	}
}

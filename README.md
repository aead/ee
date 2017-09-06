# EE - Encrypt Everything

Encrypt everything securely.

**This tool is currently not more than a demo tool - do not use it in production!** 

### Installation

**Install:** `go get -u github.com/aead/ee`

### Usage

```
Usage of ee:
  -dec string
        Decrypt data with the provided password
  -dst string
        The destination file ee will try to write to - default is STDOUT
  -enc string
        Encrypt data with the provided password
  -gen string
        Generate and print the derived key from the provided password
  -iv string
        The IV used to derive a key from the password
  -src string
        The source file ee will try to read from - default is STDIN

Examples of ee:

   Derive and print encryption key: ee -gen your-password -iv your-iv
   Encrypt and print file         : ee -enc your-password -iv your-iv -src /path/to/your/file
   Encrypted file copy            : ee -enc your-password -iv your-iv -src /path/to/your/src -dst /path/to/your/dst
   Decrypted file copy with pipes : cat /path/to/your/src | ee -dec your-password -iv your-iv > /path/to/your/dst
```


# EE - Encrypt Everything

Encrypt everything securely.

**This tool is currently not more than a demo tool - do not use it in production!!!** 

### Installation

**Install:** `go get -u github.com/aead/ee`

### Usage

En/decrypt streams by using STDIN and STDOUT:

Encrypt: `cat "input" | ee enc -pwd "your-password" -salt "your-salt" > "output"`  
Decrypt: `cat "input" | ee dec -pwd "your-password" -salt "your-salt" > "output"`


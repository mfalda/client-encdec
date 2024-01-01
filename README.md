## Description

The HTTPS protocol has enforced a higher level of robustness to several attacks; however, it is not easy to set up the required certificates on intranets, nor is it effective in the case the server confidentiality is not reliable, as in the case of cloud services, or it could be compromised. A simple method is proposed to encrypt the data on the client side, using Web Assembly. It never transfers data to the server as clear text. Searching fields in the server is made possible by an encoding scheme that ensures a stable prefix correspondence between ciphertext and plaintext. The method has been developed for a semantic medical database, and allows accessing personal data using an additional password while maintaining non-sensitive information in clear form. Web Assembly has been chosen to guarantee the fast and efficient execution of encrypting/decrypting operations and because of its characteristic of producing modules that are very robust against reverse engineering. 

If you use this library please cite:

Marco Falda and Angela Grassi: "Simple client-side encryption of personal information with Web Assembly", arXiv preprint arXiv:2312.17689, DOI: 
https://doi.org/10.48550/arXiv.2312.17689, 2023.


## Available functions

There are two main functions:

```
encryptText(pwd, text, pref_len)
```

and 

```
encryptText(pwd, text, pref_len)
```

The parameters are self-explaining.


## Compiling

Compile the source code with the command (in the script build_pkg.sh)

```
wasm-pack build --target web
```

The package will be created in the folder `/home/debian/Documents/client-encdec/pkg`


## Tests

Run the (unit) tests with

```
cargo test
```

## Benchmarking

In the file index.html there is a example form and a benchmark. It must be opened in a webserver, for instance using the simple Python HTTP server in example_server.sh:

```
python3 -m http.server
```

## License

Licensed under Apache License, Version 2.0, (http://www.apache.org/licenses/LICENSE-2.0)

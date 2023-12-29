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

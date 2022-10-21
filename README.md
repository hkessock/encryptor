# Encryptor
## A potentially useful golang sample application focused on file encryption
- Easily encrypt or decrypt files
	- Support for password (PBKDF2) based key generation
	- Support for 256-bit (32 byte) keys
	- Support for AES-GCM
- Support for file chunking and large files (e.g. 10GB)
- Easily hash a file
	- Support for SHA256
- Support for concurrency during encryption and decryption
	- Specify file chunking size during encryption
	- Specify concurrency levels for read, execute, and write operations
- Built in `--help` flag

## Usage

### Simple examples

```ts
# Encrypt, prompting for password
encryptor source.txt destination.enc

# Encrypt, supplying password
encryptor --password='some password' source.docx destination.enc

# Encrypt, supplying 256-bit key hex string
encryptor --keyhex=e0a8caca8965ae9b0de13b699012b2331acc003960c287408a55c5e133aedff6 source.mp4 destination.enc

# Decrypting, supplying password
encryptor -d --password='some password' source.enc destination.txt

# Hashing
encryptor -h source.iso
```

### Complex examples

```ts
# Encrypt, prompting for password, increasing concurrency
encryptor --readers=12 --executors=24 --writers=4 source.txt destination.enc

# Encrypt, prompting for password, increasing chunk size
encryptor --chunksize=64 source.mpeg destination.enc
```
## Options

### help

Display usage

```ts
encryptor -?
encryptor --help
```

### version

Display version information

```ts
encryptor --version
```

### decryption

Specify decryption as the action. The default action is `encryption`

```ts
encryptor -d source destination
encryptor --decrypt source destination
```
### hashing

Specify hashing as the action. The default action is `encryption`

```ts
encryptor -h source
encryptor --hash source
```
### keyhex

Specify a 32-byte (256-bit) key with a hex string.  The default behavior is to prompt the user for a password

```ts
encryptor -ke0a8caca8965ae9b0de13b699012b2331acc003960c287408a55c5e133aedff6 source destination
encryptor --keyhex='e0a8caca8965ae9b0de13b699012b2331acc003960c287408a55c5e133aedff6' source destination
```
### password

Specify a password to use during key generation. The default behavior is to prompt the user for a password

```ts
encryptor -p'some password' source destination
encryptor --password='some password' source destination
```
### chunk size

Specify the size in MB at which files are chunked. The minimum value is 1 and the maximum value is 64. The default is `8`

```ts
encryptor -c4 source destination
encryptor --chunksize=4 source destination
```
### readers

Specify the number of concurrent read workers to use. The minimum value is 1 and the maximum value is 30. The default is `6`

```ts
encryptor -r16 source destination
encryptor --readers=16 source destination
```
### executors

Specify the number of concurrent execute workers to use.  These workers operate on the data coming from the readers.  The minimum value is 1 and the maximum value is 60. The default is `12`

```ts
encryptor -e32 source destination
encryptor --executors=32 source destination
```
### writers

Specify the number of concurrent write workers to use.  These workers operate on the data coming from the executors.  The minimum value is 1 and the maximum value is 1.  This is restricted until concurrent random access writes are enabled.  The default is `1`

```ts
# Note that each of these examples will produce a clamping warning
encryptor -w32 source destination
encryptor --writers=32 source destination
```
### force

Specify that operations that would result in file overwriting should be allowed.  The default behavior is `false`

```ts
encryptor -f source destination
encryptor --force source destination
```

package main

import (
	"errors"
	"github.com/pborman/getopt/v2"
	"math"
	"os"
)

type EncryptorOptions struct {
	SourceFilename string
	TargetFilename string
	Operation      OperationEnum
	KeyHex         string
	Password       string
	ChunkSizeMB    uint
	Readers        uint8
	Executors      uint8
	Writers        uint8
	ForceOperation bool
}

type OperationEnum uint8

const (
	Encryption OperationEnum = iota
	Decryption
	FileHashing
)

const ReadersLimit uint8 = 30
const ExecutorsLimit uint8 = 60
const WritersLimit uint8 = 1 // Still researching concurrent file writing in Golang
const ChunkSizeMin uint = 1
const ChunkSizeMax uint = 64

func initializeOptions(options *EncryptorOptions) error {
	if options == nil {
		return errors.New("options is nil")
	}

	options.SourceFilename = ""
	options.TargetFilename = ""
	options.Operation = Encryption
	options.KeyHex = ""
	options.Password = ""
	options.ChunkSizeMB = 8
	options.Readers = 6
	options.Executors = 12
	options.Writers = 1
	options.ForceOperation = false

	return nil
}

// Note: We all this function to exit the process based upon some conditions, ergo no error return result
func processOpts(options *EncryptorOptions) error {
	if options == nil {
		return errors.New("options is nil")
	}

	if err := initializeOptions(options); err != nil {
		return err
	}

	decrypting := false
	help := false
	version := false
	hashing := false

	getopt.FlagLong(&help, "help", '?', "Display help")
	getopt.FlagLong(&version, "version", 0, "display version information")
	getopt.FlagLong(&decrypting, "decrypt", 'd', "Decrypt the source file instead of encrypt")
	getopt.FlagLong(&hashing, "hash", 'h', "SHA256 hash a file")
	getopt.FlagLong(&options.KeyHex, "keyhex", 'k', "Hexadecimal string representing the key material")
	getopt.FlagLong(&options.Password, "password", 'p', "The password from which we should derive key material")
	getopt.FlagLong(&options.ChunkSizeMB, "chunksize", 'c', "The maximum size, in MB, of a file before it is chunked")
	getopt.FlagLong(&options.Readers, "readers", 'r', "The number of read workers to utilize")
	getopt.FlagLong(&options.Executors, "executors", 'e', "The number of execute workers to utilize")
	getopt.FlagLong(&options.Writers, "writers", 'w', "The number of write workers to utilize")
	getopt.FlagLong(&options.ForceOperation, "force", 'f', "Should optional operations (e.g. file overwriting) be forced")

	getopt.Parse()

	if true == help {
		showHelp()
		os.Exit(0)
	}

	if true == version {
		showVersionInfo()
		os.Exit(0)
	}

	// Default operational behavior is encryption
	options.Operation = Encryption

	if decrypting == true && hashing == true {
		gLoggerStderr.Println("Hashing and decryption cannot be specified simultaneously")
		os.Exit(1)
	} else if decrypting == true {
		options.Operation = Decryption
	} else if hashing == true {
		options.Operation = FileHashing
	}

	// Exercise some constraints on worker
	if options.Readers < 1 || options.Readers > ReadersLimit {
		gLoggerStdout.Println("Read workers must be between ", ReadersLimit, " and 1")
		options.Readers = uint8(math.Max(float64(1), math.Min(float64(options.Readers), float64(ReadersLimit))))
	}
	if options.Executors < 1 || options.Executors > ExecutorsLimit {
		gLoggerStdout.Println("Execute workers must be between ", ExecutorsLimit, " and 1")
		options.Executors = uint8(math.Max(float64(1), math.Min(float64(options.Executors), float64(ExecutorsLimit))))
	}
	if options.Writers < 1 || options.Writers > WritersLimit {
		gLoggerStdout.Println("Write workers is currently restricted to ", WritersLimit)
		options.Writers = uint8(math.Max(float64(1), math.Min(float64(options.Writers), float64(WritersLimit))))
	}

	if options.ChunkSizeMB < ChunkSizeMin || options.ChunkSizeMB > ChunkSizeMax {
		gLoggerStdout.Println("Chunk size (MB) must between ", ChunkSizeMin, " and ", ChunkSizeMax)
		options.ChunkSizeMB = uint(math.Max(float64(ChunkSizeMin), math.Min(float64(options.ChunkSizeMB), float64(ChunkSizeMax))))
	}

	// We have two filenames leftover possibly
	args := getopt.Args()
	length := len(args)

	if length >= 1 {
		options.SourceFilename = args[0]
	}

	if length >= 2 {
		options.TargetFilename = args[1]
	}

	if length > 2 {
		gLoggerStderr.Println("Only two unspecified arguments can be passed - source filename and target filename\n", length, "unspecified arguments were passed")
		gLoggerStderr.Println(args)
		os.Exit(1)
	}

	return nil
}

func showHelp() {
	gLoggerStdout.Println("\nExample: encryptor [flagged options][source filename][target filename]")
	gLoggerStdout.Println("\nencryptor -d -f --password=\"my password\" my_encrypted_file.enc my_decrypted_file")
	gLoggerStdout.Println("\n\tOptions are parsed gnu style, e.g. --option=value or -ovalue and must be BEFORE unflagged arguments")
	gLoggerStdout.Println("")
	getopt.Usage()
}

func showVersionInfo() {
	versionInfo := "version: " + gVersion + " commit: " + gGitCommit
	gLoggerStdout.Println(versionInfo)
}

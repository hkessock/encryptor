package main

import (
	"bufio"
	"errors"
	"fmt"
	"log"
	"os"
	"runtime"
	"strings"
)

// Tie to a make/CI system (including build number) and version convention in the future
var gVersion = "0"
var gGitCommit = "0"
var gLoggerStdout = log.New(os.Stdout, "", 0)
var gLoggerStderr = log.New(os.Stderr, "", log.Lshortfile)
var gOptions EncryptorOptions

func main() {

	if err := processOpts(&gOptions); err != nil {
		gLoggerStderr.Println("Could not initialize encryptor: ", err.Error())
	}

	/*
		GOMAXPROCS now defaults to the value of runtime.NumCPU, so we do
		not need to increase it - Pre 1.15 (2020?) this was something
		we would have increased to n >= 2 (in case this code is backported)
	*/
	err := validateOpts(&gOptions)
	if err != nil {
		gLoggerStderr.Println("An error was encountered validating our configuration during startup: ", err.Error())
		os.Exit(1)
	}

	/*
		There are three basic operations we are capable of: encryption,
		decryption, and hashing

		Encryption and decryption are pipeline operations, hashing
		is a direct operation
	*/
	if gOptions.Operation == FileHashing {
		hash, err := hashFile(gOptions.SourceFilename)
		if err != nil {
			gLoggerStderr.Println("An error was encountered hashing a file: ", err.Error())
			os.Exit(1)
		}

		// Use fmt.Println because the output is a contract and gLoggerStdout could change
		fmt.Print(hash)
		os.Exit(0)
	}

	job, err := pipelineJobFromOpts(&gOptions)
	if err != nil {
		gLoggerStderr.Println("An error was encountered creating pipeline job from configuration: ", err.Error())
		os.Exit(1)
	}

	err = runPipelineJob(&job)
	if err != nil {
		gLoggerStderr.Println("An error was encountered executing the pipeline job\nThe error was: ", err)
		os.Exit(1)
	}
}

func validateOpts(options *EncryptorOptions) error {
	if options == nil {
		return errors.New("options passed in are nil")
	}

	var err error = nil

	// Sanitize input
	options.SourceFilename = strings.TrimSpace(options.SourceFilename)
	options.TargetFilename = strings.TrimSpace(options.TargetFilename)
	options.KeyHex = strings.TrimSpace(options.KeyHex)
	options.Password = strings.TrimSpace(options.Password)

	/*
		TBD: With more time this could be useful and informative to a
		user experiencing difficulties (which should be rare)

		The default behavior and expectations are two receive two
		filenames on the command line and encrypt or decrypt file 1
		and write the resulting data to file 2
	*/

	// Should we prompt for password? Empty or blank passwords not supported
	if options.Operation == Encryption || options.Operation == Decryption {
		if options.KeyHex == "" && options.Password == "" {
			options.Password, err = promptUserForPassword()
			if err != nil {
				return fmt.Errorf("could not obtain password")
			}
		}
	}

	return err
}

func PrintMemUsage() {
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	fmt.Printf("\nCurrent Heap Alloc = %v MiB", (memStats.Alloc/1024)/1024)
	fmt.Printf("\nTotal Alloc Cumulative = %v MiB", (memStats.TotalAlloc/1024)/1024)
	fmt.Printf("\nVirtual Address Space Reserved (Sys) = %v MiB", (memStats.Sys/1024)/1024)
}

func promptUserForPassword() (string, error) {
	password := ""

	// Blank/Empty password not allowed
	for password == "" {
		gLoggerStdout.Println("Please supply a password: ")

		// We ignore error here because it is an EOF/unexpected newline message
		scanner := bufio.NewScanner(os.Stdin)
		if scanner.Scan() {
			password = scanner.Text()
		}

		if password == "" {
			gLoggerStdout.Println("Password cannot be empty or blank")
		}
	}

	return password, nil
}

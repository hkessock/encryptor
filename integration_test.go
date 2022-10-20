package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type FilesTest struct {
	TestName      string
	FileName      string
	ChunkSizeMB   uint
	Readers       uint8
	Executors     uint8
	Writers       uint8
	KeyHex        string
	Password      string
	Data          string
	expectSuccess bool
}

//[5]int{10, 20, 30, 40, 50}
var hashFiles = []FilesTest{
	{"Known hash", "hashtarget.txt", 8, 6, 12, 1, "", "some_password_here", "c55395f0f5b1d610b01b145d6d39c68c8aee22160c63afdecd4e3c1cadc36674", true},
	{"Different hashes/blank hash", "hashtarget.txt", 8, 6, 12, 1, "", "some_password_here", "", false},
}

var e2eFiles = []FilesTest{
	// Default concurrency
	{"Tiny File", "tiny.txt", 8, 6, 12, 1, "", "some_password_here", "", true},
	{"Small File", "small.txt", 8, 6, 12, 1, "", "some_password_here", "", true},
	{"Medium File", "medium.txt", 8, 6, 12, 1, "", "some_password_here", "", true},
	{"Perfect Chunk Size Multiple File", "chunkmultiple.txt", 8, 6, 12, 1, "", "some_password_here", "", true},
	{"Zero Byte File", "zero.txt", 8, 6, 12, 1, "", "some_password_here", "", false},
	// Default concurrency using key instead of password - TBD: Pass invalid keys
	{"Tiny File", "tiny.txt", 8, 6, 12, 1, "e0a8caca8965ae9b0de13b699012b2331acc003960c287408a55c5e133aedff6", "", "", true},
	{"Small File", "small.txt", 8, 6, 12, 1, "e0a8caca8965ae9b0de13b699012b2331acc003960c287408a55c5e133aedff6", "", "", true},
	{"Medium File", "medium.txt", 8, 6, 12, 1, "e0a8caca8965ae9b0de13b699012b2331acc003960c287408a55c5e133aedff6", "", "", true},
	{"Perfect Chunk Size Multiple File", "chunkmultiple.txt", 8, 6, 12, 1, "e0a8caca8965ae9b0de13b699012b2331acc003960c287408a55c5e133aedff6", "", "", true},
	{"Zero Byte File", "zero.txt", 8, 6, 12, 1, "e0a8caca8965ae9b0de13b699012b2331acc003960c287408a55c5e133aedff6", "", "", false},
	// Restricted concurrency
	{"Restricted Concurrency - Tiny File", "tiny.txt", 8, 1, 1, 1, "", "some_password_here", "", true},
	{"Restricted Concurrency - Small File", "small.txt", 8, 1, 1, 1, "", "some_password_here", "", true},
	{"Restricted Concurrency - Medium File", "medium.txt", 8, 1, 1, 1, "", "some_password_here", "", true},
	{"Restricted Concurrency - Perfect Chunk Size Multiple File", "chunkmultiple.txt", 8, 1, 1, 1, "", "some_password_here", "", true},
	{"Restricted Concurrency - Zero Byte File", "zero.txt", 8, 1, 1, 1, "", "some_password_here", "", false},
	// Expanded concurrency
	{"Expanded Concurrency - Tiny File", "tiny.txt", 8, 32, 64, 4, "", "some_password_here", "", true},
	{"Expanded Concurrency - Small File", "small.txt", 8, 32, 64, 4, "", "some_password_here", "", true},
	{"Expanded Concurrency - Medium File", "medium.txt", 8, 32, 64, 4, "", "some_password_here", "", true},
	{"Expanded Concurrency - Perfect Chunk Size Multiple File", "chunkmultiple.txt", 8, 32, 64, 4, "", "some_password_here", "", true},
	{"Expanded Concurrency - Zero Byte File", "zero.txt", 8, 32, 64, 4, "", "some_password_here", "", false},
	// All concurrencies with small chunk sizes
	{"Tiny File - Small Chunk", "tiny.txt", 1, 6, 12, 1, "", "some_password_here", "", true},
	{"Small File - Small Chunk", "small.txt", 1, 6, 12, 1, "", "some_password_here", "", true},
	{"Medium File - Small Chunk", "medium.txt", 1, 6, 12, 1, "", "some_password_here", "", true},
	{"Restricted Concurrency - Tiny File - Small Chunk", "tiny.txt", 1, 1, 1, 1, "", "some_password_here", "", true},
	{"Restricted Concurrency - Small File - Small Chunk", "small.txt", 1, 1, 1, 1, "", "some_password_here", "", true},
	{"Restricted Concurrency - Medium File - Small Chunk", "medium.txt", 1, 1, 1, 1, "", "some_password_here", "", true},
	{"Expanded Concurrency - Tiny File - Small Chunk", "tiny.txt", 1, 32, 64, 4, "", "some_password_here", "", true},
	{"Expanded Concurrency - Small File - Small Chunk", "small.txt", 1, 32, 64, 4, "", "some_password_here", "", true},
	{"Expanded Concurrency - Medium File - Small Chunk", "medium.txt", 1, 32, 64, 4, "", "some_password_here", "", true},
	// All concurrencies with large chunk sizes
	{"Tiny File - Large Chunk", "tiny.txt", 32, 6, 12, 1, "", "some_password_here", "", true},
	{"Small File - Large Chunk", "small.txt", 32, 6, 12, 1, "", "some_password_here", "", true},
	{"Medium File - Large Chunk", "medium.txt", 32, 6, 12, 1, "", "some_password_here", "", true},
	{"Restricted Concurrency - Tiny File - Large Chunk", "tiny.txt", 32, 1, 1, 1, "", "some_password_here", "", true},
	{"Restricted Concurrency - Small File - Large Chunk", "small.txt", 32, 1, 1, 1, "", "some_password_here", "", true},
	{"Restricted Concurrency - Medium File - Large Chunk", "medium.txt", 32, 1, 1, 1, "", "some_password_here", "", true},
	{"Expanded Concurrency - Tiny File - Large Chunk", "tiny.txt", 32, 32, 64, 4, "", "some_password_here", "", true},
	{"Expanded Concurrency - Small File - Large Chunk", "small.txt", 32, 32, 64, 4, "", "some_password_here", "", true},
	{"Expanded Concurrency - Medium File - Large Chunk", "medium.txt", 32, 32, 64, 4, "", "some_password_here", "", true},
}

// Pipeline Integration tests
func Test_EndToEnd_Files(t *testing.T) {
	filesDir := getTestFilesDirectory()
	encrypted := filesDir + string(os.PathSeparator) + "temp.enc"
	decrypted := filesDir + string(os.PathSeparator) + "temp.dec"

	// Cleanup at end of test, use force option during test to overwrite
	defer func(name string) {
		_ = os.Remove(name)
	}(encrypted)
	defer func(name string) {
		_ = os.Remove(name)
	}(decrypted)

	// Let's test a series of files that differ in size and their chunk boundary qualities
	for _, testTable := range e2eFiles {

		t.Run(testTable.TestName, func(t *testing.T) {

			// We will encrypt, decrypt, and hash the source and the decrypted
			original := filesDir + string(os.PathSeparator) + testTable.FileName

			// Encrypt the file
			encryptOptions := EncryptorOptions{
				SourceFilename: original,
				TargetFilename: encrypted,
				Operation:      Encryption,
				KeyHex:         testTable.KeyHex,
				ChunkSizeMB:    testTable.ChunkSizeMB,
				Readers:        testTable.Readers,
				Executors:      testTable.Executors,
				Writers:        testTable.Writers,
				Password:       testTable.Password,
				ForceOperation: true,
			}

			job, err := pipelineJobFromOpts(&encryptOptions)
			if err != nil {
				if testTable.expectSuccess {
					t.Error(err)
				}
				return
			}

			err = runPipelineJob(&job)
			if err != nil {
				if testTable.expectSuccess {
					t.Error(err)
				}
				return
			}

			// Decrypt the encrypted file - Note that chunksize will be ignored by pipeline
			decryptOptions := EncryptorOptions{
				SourceFilename: encrypted,
				TargetFilename: decrypted,
				Operation:      Decryption,
				KeyHex:         testTable.KeyHex,
				ChunkSizeMB:    testTable.ChunkSizeMB,
				Readers:        testTable.Readers,
				Executors:      testTable.Executors,
				Writers:        testTable.Writers,
				Password:       testTable.Password,
				ForceOperation: true,
			}

			job, err = pipelineJobFromOpts(&decryptOptions)
			if err != nil {
				if testTable.expectSuccess {
					t.Error(err)
				}
				return
			}

			err = runPipelineJob(&job)
			if err != nil {
				if testTable.expectSuccess {
					t.Error(err)
				}
				return
			}

			// Hash the original and the decrypted
			hashOriginal, err := hashFile(original)
			if err != nil {
				if testTable.expectSuccess {
					t.Error(err)
				}
				return
			}

			hashDecrypted, err := hashFile(decrypted)
			if err != nil {
				if testTable.expectSuccess {
					t.Error(err)
				}
				return
			}

			if hashOriginal != hashDecrypted {
				if testTable.expectSuccess {
					t.Error("Hashes of the original and the decrypted file do not match")
				}
				return
			}
		})
	}
}

// Non-pipeline Feature tests
func Test_Hashing(t *testing.T) {
	filesDir := getTestFilesDirectory()

	for _, testTable := range hashFiles {

		t.Run(testTable.TestName, func(t *testing.T) {

			// Hash the file and compare to the expected test result
			fileName := filesDir + string(os.PathSeparator) + testTable.FileName
			expectedHash := testTable.Data

			fileHash, err := hashFile(fileName)
			if err != nil {
				if testTable.expectSuccess {
					t.Error(err)
				}
				return
			}

			if expectedHash != fileHash {
				if testTable.expectSuccess {
					t.Error(err)
				}
			}
		})
	}
}

// TBD: Replace 'encryptor' with environment var(s)
func getTestFilesDirectory() string {
	workDir, _ := os.Getwd()
	for !strings.HasSuffix(workDir, "encryptor") {
		workDir = filepath.Dir(workDir)
	}

	return workDir + string(os.PathSeparator) + "test_files"
}

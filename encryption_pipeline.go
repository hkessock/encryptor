package main

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
)

type PipelineJob struct {
	NumReaders     uint
	NumExecutors   uint
	NumWriters     uint
	SourceFilename string
	TargetFilename string
	ForceOperation bool
	ChunkSizeMB    uint
	Operation      OperationEnum
	Cipher         CipherEnum
	CipherMode     CipherModeEnum
	KeyMaterial    []byte
}

type ChunkReadRequest struct {
	ChunkID    uint
	RangeStart int64
	RangeEnd   int64
}

func pipelineJobFromOpts(options *EncryptorOptions) (PipelineJob, error) {
	if options == nil {
		return PipelineJob{}, errors.New("options is nil")
	}

	/*
		Note: the options passed in are expected to be validated and
		non-pipeline jobs (like generating a file hash) are expected
		to be preempted before arriving here - e.g. either keyhex or
		password will have been specified

		Some validation happens here because in the future we may want
		to support other ciphers, modes, and key sizes (e.g. DES, IDEA,
		Blowfish, RC4/5/6, CBC/CTR/ECB, 128 bits, 512 bits...)
	*/
	var keyMaterial []byte
	var err error

	if options.KeyHex != "" {
		keyMaterial, err = hex.DecodeString(options.KeyHex)
		if err != nil {
			return PipelineJob{}, errors.New("error decoding hex string for key material")
		}
	} else if options.Password != "" {
		keyMaterial, err = generateKey256FromString(options.Password)
		if err != nil {
			return PipelineJob{}, errors.New("error generating key material from password")
		}
	}

	// Currently only working with 256-bit keys
	if len(keyMaterial) != 32 {
		return PipelineJob{}, errors.New("currently only 256 bit (32 byte) keys are supported, key material length is " + strconv.Itoa(len(keyMaterial)) + " bytes")
	}

	job := PipelineJob{
		NumReaders:     uint(options.Readers),
		NumExecutors:   uint(options.Executors),
		NumWriters:     uint(options.Writers),
		SourceFilename: options.SourceFilename,
		TargetFilename: options.TargetFilename,
		ForceOperation: options.ForceOperation,
		ChunkSizeMB:    options.ChunkSizeMB,
		Operation:      options.Operation,
		Cipher:         AES,
		CipherMode:     GCM,
		KeyMaterial:    keyMaterial,
	}

	return job, nil
}

/*
	Using an Error group would have been cool, but it's overkill
	for non-async operations since we don't need context shutdowns
	we need exit-process shutdowns
*/
func runPipelineJob(job *PipelineJob) error {
	if job == nil {
		return errors.New("pipeline job is nil")
	}

	// Make buffered error channel with a capacity of one for each stage of our pipeline
	pipelineErrors := make(chan error, 3)

	/*
		If we are encrypting:
			Collect stat information on the source file
			Compute the number of chunks we'll be generating
			Compute the header for our write stage

		If we are decrypting:
			Collect stat information on the source file
			Read the header length indicator
			Consume the header
			Compute the number of chunks and their size from the header
	*/
	stats, err := getStatsFromFile(job.SourceFilename)
	if err != nil {
		return errors.New("failed to obtain stats for source file, error was: " + err.Error())
	}

	// The number of chunks is equal to sizeBytes / chunkSizeBytes
	sizeBytes := stats.Size()
	chunkSizeBytes := bytesFromMB(job.ChunkSizeMB)

	// Be wary of a perfect chunk match, if extra bytes leftover add a chunk
	numChunks := uint32(sizeBytes / chunkSizeBytes)
	if sizeBytes%chunkSizeBytes != 0 {
		numChunks++
	}

	// Only used with decryption, but we pass currently in all cases (TBD fix this)
	header := EncryptedFileHeader{}
	endOfHeader := 0

	if job.Operation == Decryption {
		// We're going to make sure it's an encrypted file and modify some values
		header, endOfHeader, err = getEncryptedFileHeaderFromFile(job.SourceFilename)
		if err != nil {
			return fmt.Errorf("failed to retrieve encryption header from file: %w", err)
		}

		numChunks = header.NumChunks
	}

	/*
		There are many, many, many ways to solve this problem, we are
		going to do it by creating, what will effectively be, a sliding
		window of channels that stream data from our read stage through
		the executor stage (where data can be operated upon) and finally
		into the write stage - as data is read, executed, and written,
		blobs of data in the read and execute stages pass ownership to
		the write stage which starts writing as soon as possible so that
		each blob is available to the GC as soon as possible

		Each chunk has an unbuffered channel of size 1 so that each worker
		can block on the front of the file to help ensure that we do not
		accumulate too much of a large file in memory as the reader, executor,
		and writer 'slide' through the file

		The overhead of having many channels is negligible since they are only
		carrying pointers to []byte

		TBD: determine if golang's IO supports pwrite like capabilities in order
		to multi-thread writing which would release memory pressure even faster
		than a linear writing approach
	*/
	var readChannelsSlice = make([]chan *ChunkReadRequest, numChunks)
	for i := range readChannelsSlice {
		readChannelsSlice[i] = make(chan *ChunkReadRequest, 1)
	}

	var executeChannelsSlice = make([]chan *[]byte, numChunks)
	for i := range executeChannelsSlice {
		executeChannelsSlice[i] = make(chan *[]byte, 1)
	}

	var writeChannelsSlice = make([]chan *[]byte, numChunks)
	for i := range writeChannelsSlice {
		writeChannelsSlice[i] = make(chan *[]byte, 1)
	}

	/*
		Our sub pipelines will generate and share data amongst themselves over
		n * chunks channels - this could be a lot of channels for a small chunk
		size and a large file - so enforce some realistic chunk sizes for files
		(e.g. chunk size is >= (filesize/250))

		If decrypting, read pipeline needs to generate read ranges for workers
		that are offset by (header length indicator + header length) bytes

		If encrypting, write pipeline needs to generate write ranges (if we
		parallelize) that are offset by (header length indicator + header length)
		bytes
	*/
	go readStage(job.Operation, job.SourceFilename, job.ChunkSizeMB, stats, header, endOfHeader, pipelineErrors, job.NumReaders, readChannelsSlice, executeChannelsSlice)
	go executeStage(job.Operation, job.KeyMaterial, pipelineErrors, job.NumExecutors, executeChannelsSlice, writeChannelsSlice)
	go writeStage(job.Operation, job.TargetFilename, job.ForceOperation, numChunks, job.ChunkSizeMB, pipelineErrors, job.NumWriters, writeChannelsSlice)

	// Block on buffered read until we get 3 nils or we get an error
	for i := 0; i < 3; i++ {
		err := <-pipelineErrors
		if err != nil {
			return errors.New("error occurred during pipeline process: " + err.Error())
		}
	}

	return nil
}

func bytesFromMB(mb uint) int64 {
	return int64(mb * 1024 * 1024)
}

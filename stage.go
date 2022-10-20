package main

import (
	"errors"
	"os"
	"runtime"
)

/*
	Golang still doesn't support slices of directional channels,
	so these are two-way, but we'll only use one direction - this
	is better that deep conversions using unsafe in my opinion, and
	arguably more readable
*/

// Dev note: Read from read channels, write to execute channels
func readStage(op OperationEnum, fileName string, chunkSizeMB uint, stats os.FileInfo, fileHeader EncryptedFileHeader, endOfHeader int, ch chan<- error, numWorkers uint, readChannels []chan *ChunkReadRequest, executeChannels []chan *[]byte) {
	var err error = nil
	defer func() { ch <- err }()

	chunkSizeBytes := bytesFromMB(chunkSizeMB)

	// Follow the same pattern as the main pipeline for our concurrent reads
	readWorkerErrors := make(chan error, numWorkers)

	for i := uint(1); i <= numWorkers; i++ {
		go readWorker(op, fileName, readWorkerErrors, i, numWorkers, readChannels, executeChannels)
	}

	/*
		The read pipeline is the start - let's prime the pump!

		An encryption operation results in differently generated ranges
		than decryption - as decryption has chunk count and size specified
		by the file's header because we have to use the chunk count and
		size specified during encryption
	*/

	for i := uint(0); i < uint(len(readChannels)); i++ {
		request := ChunkReadRequest{
			ChunkID: i + 1,
		}

		// Encryption is simple - start and end are iterations of chunk size
		if op == Encryption {
			request.RangeStart = int64(i) * chunkSizeBytes
			request.RangeEnd = request.RangeStart + chunkSizeBytes
		} else if op == Decryption {
			/*
				We rely on the chunk size in bytes from file header because
				some encryption schemes can have complicated paddings and
				encoding schemes that are more easily managed in this manner.

				Because we only support AES-GCM right now, everything is the same
				as reading an unencrypted file (because AES-GCM encrypts in place)
				except the chunk size has the 12 byte nonce/iv prefixed and the
				16 byte authentication tag (we only support AES-GCM right now)
				postfixed
			*/

			// Don't forget the header offset! TBD: Remove AES GCM hard coded values
			request.RangeStart = int64(endOfHeader) + (int64(i) * (int64(AESNonceSize) + chunkSizeBytes + int64(AESTagSize)))
			request.RangeEnd = request.RangeStart + int64(AESNonceSize) + chunkSizeBytes + int64(AESTagSize)
		} else {
			err = errors.New("unsupported operation specified in read stage")
			return
		}

		/*
			Make sure we're not past the end of the file (meaning we
			should be the last chunk as well)
			Also note that the extreme edge case where the header offset of
			an encrypted file could place a RangeStart value to pass the
			EOF is handled by the fact that encrypted files are constructed
			in such a way as to make this impossible
		*/
		if request.RangeEnd >= stats.Size() {
			request.RangeEnd = stats.Size()
		}

		readChannels[i] <- &request
	}

	for i := uint(0); i < numWorkers; i++ {
		readError := <-readWorkerErrors
		if readError != nil {
			err = errors.New("read worker error: " + readError.Error())
		}
	}

	// No defer because returning from errors results in process exit anyhow
	close(readWorkerErrors)
	runtime.GC()
}

// Dev note: Read from execute channels, write to write channels
func executeStage(op OperationEnum, keyMaterial []byte, ch chan<- error, numWorkers uint, executeChannels []chan *[]byte, writeChannels []chan *[]byte) {
	var err error = nil
	defer func() { ch <- err }()

	// Currently, we only support AES-GCM for encryption/decryption
	if len(keyMaterial) != 32 {
		err = errors.New("execute stage currently only supports 256-bit (32 byte) key materials")
		return
	}

	executeWorkerErrors := make(chan error, numWorkers)

	for i := uint(1); i <= numWorkers; i++ {
		go executeWorker(op, keyMaterial, executeWorkerErrors, i, numWorkers, executeChannels, writeChannels)
	}

	// The read pipeline will feed our workers for us

	for i := uint(0); i < numWorkers; i++ {
		executeError := <-executeWorkerErrors
		if executeError != nil {
			err = errors.New("execute worker error: " + executeError.Error())
		}
	}

	// No defer because returning from errors results in process exit anyhow
	close(executeWorkerErrors)
	runtime.GC()
}

// HANS DEBUG - PRODUCE HEADER AND PASS TO THIS STAGE WHEN NEEDED
func writeStage(op OperationEnum, fileName string, force bool, numChunks uint32, chunkSizeMB uint, ch chan<- error, numWorkers uint, writeChannels []chan *[]byte) {
	var err error = nil
	var header EncryptedFileHeader
	defer func() { ch <- err }()

	/*
		The number of write workers is capped at 1 while concurrent random access
		writes are researched (e.g. pre-writing 0 based file and then overwriting)
	*/
	numWorkers = 1

	if op == Encryption {
		/*
			We need to generate an encrypted file header which consists of a uint16
			indicating the size of the header and the header itself arranged as a
			byte array with the uint16 leading and encoded in little endian format
			followed by the header itself - a JSON string of UTF-8 characters that
			maps to the EncryptedFileHeader structure

			This data prefixes our encrypted files
		*/
		header = EncryptedFileHeader{
			FormatVersion:  "1.0",
			NumChunks:      numChunks,
			ChunkSizeBytes: bytesFromMB(chunkSizeMB),
			Algorithm:      "AES",
			Mode:           "GCM",
			KeySize:        256,
		}
	}

	// Follow the same pattern as the main pipeline for our concurrent writes
	writeWorkerErrors := make(chan error, numWorkers)

	/*
		We pass the header because it is potentially of use
		to every worker during the writing of encrypted data
		As of today it is primarily of use to the first chunk
		writer, so it can prefix the file with header data which
		is needed during decryption - for future proofing we
		send a copy rather than share a pointer
	*/
	for i := uint(1); i <= numWorkers; i++ {
		go writeWorker(op, header, fileName, force, writeWorkerErrors, i, numWorkers, writeChannels)
	}

	for i := uint(0); i < numWorkers; i++ {
		writeError := <-writeWorkerErrors
		if writeError != nil {
			err = errors.New("write worker error: " + writeError.Error())
		}
	}

	// No defer because returning from errors results in process exit anyhow
	close(writeWorkerErrors)
}

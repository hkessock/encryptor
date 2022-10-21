package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
)

// We pass op into this worker because we will need it for some future cipher/block algorithms and modes
func readWorker(op OperationEnum, fileName string, ch chan<- error, id uint, numWorkers uint, readChannels []chan *ChunkReadRequest, executeChannels []chan *[]byte) {
	var err error = nil
	defer func() { ch <- err }()

	// We want our own file descriptor, and we'll use it for each chunk we read
	fileName = strings.TrimSpace(fileName)
	if fileName == "" {
		err = errors.New("empty string passed in for filename")
		return
	}

	file, err := os.Open(fileName)

	if err != nil {
		if os.IsNotExist(err) {
			err = fmt.Errorf("source file does not exist: %w", err)
		} else if os.IsPermission(err) {
			err = fmt.Errorf("could not open source file due to insufficient permissions: %w", err)
		} else {
			err = fmt.Errorf("could not open source file due to unexpected error: %w", err)
		}

		return
	}

	defer func(file *os.File) {
		_ = file.Close()
	}(file)

	// Do our share of the work non-linearly based upon the number of workers and our id
	idMatch := id

	if idMatch == numWorkers {
		idMatch = 0
	}

	for i := uint(1); i <= uint(len(readChannels)); i++ {
		if i%numWorkers == idMatch {
			// Work on this channel
			request := <-readChannels[i-1]
			close(readChannels[i-1])

			// Read the amount of data we have been told to - if we read EOF that's an error
			seek, err := file.Seek(request.RangeStart, 0)
			if err != nil || seek != request.RangeStart {
				err = fmt.Errorf("could not set file position to correct location: %w", err)
				return
			}

			// Allocate space for the chunk and create a buffered IO reader to consume with
			bytesToRead := request.RangeEnd - request.RangeStart
			chunkData := make([]byte, bytesToRead)

			reader := bufio.NewReader(file)
			bytesRead, err := io.ReadFull(reader, chunkData)
			if err != nil || int64(bytesRead) != bytesToRead {
				err = fmt.Errorf("error occurred durring read of file: %w", err)
				return
			}

			// Pass this data to the execute stage's workers
			executeChannels[i-1] <- &chunkData

			/*
				Go's userspace scheduler is not preemptive, it's a form of cooperative,
				so yield in this stage as we do not want it getting too far ahead of
				our other goroutines
			*/
			runtime.Gosched()
		}
	}
}

func executeWorker(op OperationEnum, keyMaterial []byte, ch chan<- error, id uint, numWorkers uint, executeChannels []chan *[]byte, writeChannels []chan *[]byte) {
	var err error = nil
	defer func() { ch <- err }()

	// Do our share of the work non-linearly based upon the number of workers and our id
	idMatch := id

	if idMatch == numWorkers {
		idMatch = 0
	}

	for i := uint(1); i <= uint(len(executeChannels)); i++ {
		if i%numWorkers == idMatch {
			// Work on this channel
			chunkData := <-executeChannels[i-1]
			close(executeChannels[i-1])

			if op == Encryption {
				chunkData, err = encryptBlobAESGCM256(chunkData, keyMaterial)
			} else if op == Decryption {
				chunkData, err = decryptBlobAESGCM256(chunkData, keyMaterial)
			} else {
				err = errors.New("bad operation found in execute pipeline")
				return
			}

			if err != nil {
				err = errors.New("failed cryptographic transformation, ensure the correct password or key is being used: " + err.Error())
				return
			}

			writeChannels[i-1] <- chunkData
			runtime.Gosched()
		}
	}
}

func writeWorker(op OperationEnum, header EncryptedFileHeader, fileName string, force bool, ch chan<- error, id uint, numWorkers uint, writeChannels []chan *[]byte) {
	var err error = nil
	defer func() { ch <- err }()

	fileName = strings.TrimSpace(fileName)
	if fileName == "" {
		err = errors.New("empty string passed in for filename")
		return
	}

	// Does the file already exist?  We'll try to get info on it
	fileExists := true

	_, err = os.Stat(fileName)
	if os.IsNotExist(err) {
		fileExists = false
	} else if os.IsPermission(err) {
		err = fmt.Errorf("permissions error trying to access file for writing: %w", err)
		return
	}

	if true == fileExists && force == false {
		err = errors.New("file already exists and overwriting was not specified")
		return
	}

	/*
		In case we have time to implement concurrent random access rights,
		let's create a file descriptor for this worker to use - otherwise
		we could simply do all this work in the write stage function
	*/
	file, err := os.Create(fileName)
	if err != nil {
		err = fmt.Errorf("could not open file for writing: %w", err)
	}

	// Because the close is for a file we are writing to, handle errors on defer
	defer func(file *os.File) {
		err := file.Close()
		if err != nil {
			err = fmt.Errorf("error closing file we were writing to: %w", err)
		}
	}(file)

	writer := bufio.NewWriter(file)

	/*
		Attention: if we get the time to implement concurrent/parallelized writes
		then ensure we consider the complete header length when computing ranges
		for channel data pwrites (header length indicator + header UTF-8 length)

		For now, we have 1 worker, meaning if our op is encryption, we prefix the
		file with the complete header data
	*/
	if op == Encryption {
		headerBytes, err := getCompleteEncryptedFileHeaderAsBytes(&header)
		if err != nil {
			err = fmt.Errorf("failed to assemble encrypted file header: %w", err)
			return
		}

		// Write the header
		written, err := writer.Write(headerBytes)
		if err != nil || written != len(headerBytes) {
			err = fmt.Errorf("failed to write data to file: %w", err)
			return
		}
	}

	// Do our share of the work non-linearly based upon the number of workers and our id
	idMatch := id

	if idMatch == numWorkers {
		idMatch = 0
	}

	for i := uint(1); i <= uint(len(writeChannels)); i++ {
		if i%numWorkers == idMatch {
			// Work on this channel
			chunkData := <-writeChannels[i-1]
			close(writeChannels[i-1])

			/*
				Lots of confusing information talking about concurrent writes from different
				file descriptors - this is possible in Linux, but I don't know golang's IO well
				enough to know if this works - if I have time, will experiment
			*/
			written, err := writer.Write(*chunkData)
			if err != nil || written != len(*chunkData) {
				err = fmt.Errorf("failed to write data to file: %w", err)
				return
			}

			err = writer.Flush()
			if err != nil {
				err = fmt.Errorf("flush on write failed: %w", err)
			}
		}
	}
}

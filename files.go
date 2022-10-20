package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

type EncryptedFileHeader struct {
	FormatVersion  string
	NumChunks      uint32
	ChunkSizeBytes int64
	Algorithm      string
	Mode           string
	KeySize        int
}

/*
	Next file steps would be to enforce versioning across all
	aspects of file persistence, but this is a project, not a
	product, so I only get about 20 hours or so to work on it
	- so, for now, we use version info in the file header
*/

func getEncryptedFileHeaderFromFile(fileName string) (EncryptedFileHeader, int, error) {
	fileName = strings.TrimSpace(fileName)
	if fileName == "" {
		return EncryptedFileHeader{}, 0, errors.New("empty string passed in for filename")
	}

	file, err := os.Open(fileName)
	if err != nil {
		if os.IsNotExist(err) {
			err = fmt.Errorf("file does not exist: %w", err)
		} else if os.IsPermission(err) {
			err = fmt.Errorf("could not open file due to insufficient permissions: %w", err)
		} else {
			err = fmt.Errorf("could not open file due to unexpected error: %w", err)
		}

		return EncryptedFileHeader{}, 0, err
	}

	defer func(file *os.File) {
		_ = file.Close()
	}(file)

	stats, err := file.Stat()
	if err != nil {
		return EncryptedFileHeader{}, 0, fmt.Errorf("could not obtain file stat info: %w", err)
	}

	// Theoretically an encrypted file could be a header length indicator specifying 0 and a 1 byte file
	if stats.Size() < int64(3) {
		return EncryptedFileHeader{}, 0, fmt.Errorf("the file is not a recognized format")
	}

	// Read the first two bytes for the header length indicator
	bytesToRead := 2
	hliBytes := make([]byte, bytesToRead)

	reader := bufio.NewReader(file)
	bytesRead, err := io.ReadFull(reader, hliBytes)
	if err != nil || bytesRead != bytesToRead {
		return EncryptedFileHeader{}, 0, fmt.Errorf("error occurred trying to read HLI from file: %w", err)
	}

	// We need to know the offset to the end of the header
	offset := 2

	headerLength, err := uint16FromBytes(&hliBytes)
	if err != nil {
		return EncryptedFileHeader{}, 0, fmt.Errorf("could not derive HLI from data")
	}

	// Read the header
	headerBytes := make([]byte, headerLength)

	bytesRead, err = io.ReadFull(reader, headerBytes)
	if err != nil || bytesRead != int(headerLength) {
		return EncryptedFileHeader{}, 0, fmt.Errorf("file may not be encrypted, could not read header: %w", err)
	}

	encryptedFileHeader, err := encryptionHeaderFromBytes(&headerBytes)
	if err != nil {
		return EncryptedFileHeader{}, 0, fmt.Errorf("file may not be encrypted, could not read header: %w", err)
	}

	offset += int(headerLength)

	return encryptedFileHeader, offset, nil
}

func getEncryptedFileHeaderFromBytes(data *[]byte) (*EncryptedFileHeader, int, error) {
	// Must at least have a header length indicator (theoretically could be header of length 0)
	if data == nil || len(*data) < 2 {
		return &EncryptedFileHeader{}, 0, errors.New("nil or too small array passed in as data")
	}

	// Start computing the length of the HLI and header together (useful as a file offset during reads and writes)
	var offset int = 0

	// The first two bytes are the HLI (telling us how much header data follows)
	offset += 2
	headerLength, err := uint16FromBytes(data)
	if err != nil {
		return &EncryptedFileHeader{}, 0, fmt.Errorf("failed to obtain HLI from data")
	}

	offset += int(headerLength)

	// Get the header from the header bytes (skip over the HLI)
	subSlice := (*data)[2:]
	encryptedFileHeader, err := encryptionHeaderFromBytes(&subSlice)
	if err != nil {
		return &EncryptedFileHeader{}, 0, fmt.Errorf("failed to derive file encryption header from data")
	}

	return &encryptedFileHeader, offset, nil
}

func getCompleteEncryptedFileHeaderAsBytes(header *EncryptedFileHeader) ([]byte, error) {
	if header == nil {
		return []byte{}, errors.New("nil passed in for header")
	}

	// Serialize the structure to a JSON byte array
	jsonBytes, err := json.Marshal(header)
	if err != nil {
		return []byte{}, fmt.Errorf("marshaling header data failed: %w", err)
	}

	// Now that we can measure the header array, let's generate our header length indicator
	headerLength := uint16(len(jsonBytes))

	// Use a binary writer on an expandable Buffer
	headerBuffer := new(bytes.Buffer)

	err = binary.Write(headerBuffer, binary.LittleEndian, headerLength)
	if err != nil {
		return []byte{}, fmt.Errorf("failed to binary write header length indicator: %w", err)
	}

	hliBytes := headerBuffer.Bytes()

	// Concatenate the HLI and the Header JSON into one complete header
	return append(hliBytes, jsonBytes...), nil
}

func uint16FromBytes(data *[]byte) (uint16, error) {
	if data == nil || len(*data) < 2 {
		return 0, errors.New("must supply at least 2 bytes to convert bytes to uint16")
	}
	num := binary.LittleEndian.Uint16(*data)
	return num, nil
}

func bytesFromUint16(num uint16) ([]byte, error) {
	headerBuffer := new(bytes.Buffer)

	err := binary.Write(headerBuffer, binary.LittleEndian, num)
	if err != nil {
		return []byte{}, fmt.Errorf("binary write failed converting uint16 to bytes: %w", err)
	}

	return headerBuffer.Bytes(), nil
}

func bytesFromEncryptionHeader(header *EncryptedFileHeader) ([]byte, error) {
	jsonBytes, err := json.Marshal(header)
	if err != nil {
		return []byte{}, fmt.Errorf("marshaling failed: %w", err)
	}
	return jsonBytes, nil
}

func encryptionHeaderFromBytes(data *[]byte) (EncryptedFileHeader, error) {
	if data == nil {
		return EncryptedFileHeader{}, errors.New("nil passed in for data")
	}

	var header EncryptedFileHeader

	err := json.Unmarshal(*data, &header)
	if err != nil {
		return EncryptedFileHeader{}, fmt.Errorf("unmarshaling failed: %w", err)
	}
	return header, nil
}

func getStatsFromFile(fileName string) (os.FileInfo, error) {
	fileName = strings.TrimSpace(fileName)
	if fileName == "" {
		return nil, errors.New("empty string passed in for filename to get stats")
	}

	file, err := os.Open(fileName)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("file does not exist: %w", err)
		} else if os.IsPermission(err) {
			return nil, fmt.Errorf("could not retrieve stats for file due to insufficient permissions: %w", err)
		}

		return nil, fmt.Errorf("could not retrieve stats for file due to unexpected error: %w", err)
	}

	defer func(file *os.File) {
		_ = file.Close()
	}(file)

	return file.Stat()
}

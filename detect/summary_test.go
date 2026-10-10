package detect

import (
	"strconv"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCommitsScannedConcurrent(t *testing.T) {
	d := &Detector{
		commitMutex: &sync.Mutex{},
		commitMap:   make(map[string]bool),
	}

	const goroutines = 50
	const distinctCommits = 50

	var wg sync.WaitGroup
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for c := 0; c < distinctCommits*2; c++ {
				// Half the additions are duplicates of the same commit.
				d.addCommit("commit-" + strconv.Itoa(c%distinctCommits))
			}
		}()
	}
	wg.Wait()

	// No loss or double counting under concurrent scanning.
	assert.Equal(t, distinctCommits, d.CommitsScanned())
}

func TestCommitsScannedEmpty(t *testing.T) {
	d := &Detector{
		commitMutex: &sync.Mutex{},
		commitMap:   make(map[string]bool),
	}
	// Non-git scans report an explicit zero instead of a missing value.
	assert.Equal(t, 0, d.CommitsScanned())
}

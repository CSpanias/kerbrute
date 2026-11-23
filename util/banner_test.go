package util

import (
	"io/ioutil"
	"os"
	"strings"
	"testing"
)

func TestBannerIdentifiesForkAndOriginalAuthor(t *testing.T) {
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	original := os.Stdout
	os.Stdout = writer
	defer func() { os.Stdout = original }()

	PrintBanner()
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	output, err := ioutil.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{
		"Ronnie Flathers @ropnop",
		"Fork maintained by CSpanias",
	} {
		if !strings.Contains(string(output), expected) {
			t.Errorf("banner does not contain %q: %s", expected, output)
		}
	}
}

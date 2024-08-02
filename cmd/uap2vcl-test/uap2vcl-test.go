package main

import (
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"

	"gopkg.in/yaml.v2"
)

type TestFile struct {
	TestCases []map[string]string `yaml:"test_cases"`
}

func main() {
	var path string
	var type_ string
	var varnish string
	flag.StringVar(&path, "tests", "test_device.yaml", "YAML test file")
	flag.StringVar(&type_, "type", "device", "type of test to run (ua, os, device)")
	flag.StringVar(&varnish, "varnish", "http://localhost:6081/", "varnish URL")
	flag.Parse()

	data, err := os.ReadFile(path)
	if err != nil { panic(err) }

	var testFile TestFile
	err = yaml.Unmarshal(data, &testFile)
	if err != nil { panic(err) }

	client := &http.Client{}

	var fields []string

	switch type_ {
	default:
		panic(fmt.Errorf("unknown type: %s", type_))
	case "ua":
		fields = []string{ "family", "major", "mino", "patch" }
	case "os":
		fields = []string{ "family", "major", "minor", "patch", "patch_minor" }
	case "device":
		fields = []string{ "family", "brand", "model" }
	}

	e := false
	for _, tc := range testFile.TestCases {
		req, err := http.NewRequest("GET", varnish, nil)
		if err != nil { panic(err) }
		req.Header.Add("user-agent", tc["user_agent_string"])
		resp, err := client.Do(req)
		if err != nil { panic(err) }
		io.ReadAll(resp.Body)

		var hdr string
		for _, field := range fields {
			hdr = type_ + "-" + field
			if resp.Header.Get(hdr) != tc[field] {
				e = true
				fmt.Printf("wrong %s for %s:\n\t got (%s), expected (%s)\n",
					hdr, tc["user_agent_string"], resp.Header.Get(hdr), tc[field])
			}
		}
	}
	if e {
		fmt.Printf("ERROOOOOOOOOOOOOOOOOOOOOOOOOR")
		os.Exit(1)
	}
}

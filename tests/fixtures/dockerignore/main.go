// Optional independent matcher oracle: go run -mod=mod .
package main

import (
    "encoding/json"
    "fmt"
    "os"
    "strings"
    "github.com/moby/patternmatcher"
    "github.com/moby/patternmatcher/ignorefile"
)

func main() {
    data, err := os.ReadFile("patterns.json"); if err != nil { panic(err) }
    var cases []struct { Policy string; Paths [][]json.RawMessage }
    if err = json.Unmarshal(data, &cases); err != nil { panic(err) }
    checked := 0
    for _, c := range cases {
        patterns, err := ignorefile.ReadAll(strings.NewReader(c.Policy)); if err != nil { panic(err) }
        matcher, err := patternmatcher.New(patterns); if err != nil { panic(err) }
        for _, pair := range c.Paths {
            var path string; var want bool
            if err = json.Unmarshal(pair[0], &path); err != nil { panic(err) }
            if err = json.Unmarshal(pair[1], &want); err != nil { panic(err) }
            got, err := matcher.MatchesOrParentMatches(path)
            if err != nil || got != want { panic(fmt.Sprintf("policy=%q path=%q got=%v want=%v err=%v", c.Policy, path, got, want, err)) }
            checked++
        }
    }
    fmt.Printf("Moby patternmatcher v0.6.0: %d expectations verified\n", checked)
}

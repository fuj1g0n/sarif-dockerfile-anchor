// Package dockerfile parses a Dockerfile into lines and answers the two
// location questions the anchoring logic needs:
//
//   - which FROM line is the final build stage (the scanned image's base), and
//   - which line installs/downloads a given OS package.
package dockerfile

import (
	"regexp"
	"strings"
)

var reFrom = regexp.MustCompile(`(?i)^FROM\s`)

// Dockerfile holds the raw lines of a Dockerfile plus a small regexp cache.
type Dockerfile struct {
	Lines []string
	cache map[string]*regexp.Regexp
}

// Parse splits content into lines, matching Python's str.splitlines() semantics
// (split on CR/LF/CRLF, drop a single trailing empty line).
func Parse(content string) *Dockerfile {
	content = strings.ReplaceAll(content, "\r\n", "\n")
	content = strings.ReplaceAll(content, "\r", "\n")
	var lines []string
	if content != "" {
		lines = strings.Split(content, "\n")
		if n := len(lines); n > 0 && lines[n-1] == "" {
			lines = lines[:n-1]
		}
	}
	return &Dockerfile{Lines: lines, cache: map[string]*regexp.Regexp{}}
}

// FinalStageFromLine returns the 1-based line of the last FROM instruction --
// the final build stage, whose base image the built image is based on. (Docker
// builds the last stage by default, so its FROM is the scanned image's base.)
// Falls back to line 1 when the Dockerfile has no FROM.
func (d *Dockerfile) FinalStageFromLine() int {
	last := 0
	for i, raw := range d.Lines {
		if reFrom.MatchString(strings.TrimSpace(raw)) {
			last = i + 1
		}
	}
	if last != 0 {
		return last
	}
	return 1
}

// InstallLine returns the 1-based Dockerfile line that installs/downloads the
// named package, using the deb heuristic: the name used as a ".deb" filename
// ("<name>_") or an apt version pin ("<name>="). A leading boundary prevents
// matching inside a longer package name (e.g. "libcurl4" must not match the
// "curl" inside "xlibcurl4"). Go's RE2 has no look-behind, so the boundary is
// expressed as an alternation that consumes the preceding byte.
func (d *Dockerfile) InstallLine(name string) (int, bool) {
	if name == "" {
		return 0, false
	}
	re, ok := d.cache[name]
	if !ok {
		re = regexp.MustCompile(`(?:^|[^A-Za-z0-9.+_-])` + regexp.QuoteMeta(name) + `[_=]`)
		d.cache[name] = re
	}
	for i, line := range d.Lines {
		if re.MatchString(line) {
			return i + 1, true
		}
	}
	return 0, false
}

// LineLength returns the byte length of the 1-based line (0 if out of range).
func (d *Dockerfile) LineLength(line int) int {
	if line < 1 || line > len(d.Lines) {
		return 0
	}
	return len(d.Lines[line-1])
}

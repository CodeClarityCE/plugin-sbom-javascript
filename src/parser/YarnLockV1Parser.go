package parser

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/CodeClarityCE/plugin-sbom-javascript/src/types/schemas"

	"github.com/pkg/errors"
)

//
// Source: https://github.com/iseki0/go-yarnlock
// Modified for our purposes
// Licensed under MIT
//

type _ValueType int

const (
	_TokenValueVoid _ValueType = iota
	_TokenValueInt
	_TokenValueString
	_TokenValueBool
)

type _TokenKind int

const (
	_TokenBoolean _TokenKind = iota + 1
	_TokenString
	_TokenIdentifier
	_TokenEOF
	_TokenColon
	_TokenNewLine
	_TokenComment
	_TokenIndent
	_TokenInvalid
	_TokenNumber
	_TokenComma
)

type _Token struct {
	line  int
	col   int
	kind  _TokenKind
	value _TokenValue
}

type _TokenValue struct {
	vInt    int
	vString string
	vBool   bool
	valid   bool
	vType   _ValueType
}

func (t _TokenValue) MarshalText() ([]byte, error) {
	switch t.vType {
	case _TokenValueInt:
		return []byte(strconv.Itoa(t.vInt)), nil
	case _TokenValueBool:
		return []byte(strconv.FormatBool(t.vBool)), nil
	case _TokenValueString:
		return []byte(t.vString), nil
	default:
		return []byte("void"), nil
	}
}

func (t *_TokenValue) IsEmpty() bool {
	return !t.valid
}

func (t *_Token) isString() bool {
	return t.value.vType == _TokenValueString
}

type _Tokenizer struct {
	lastNewLine bool
	line        int
	col         int
	tokens      []_Token
}

func (t *_Tokenizer) buildToken(tt _TokenKind, value interface{}) {
	tk := _Token{
		line:  t.line,
		col:   t.col,
		kind:  tt,
		value: _TokenValue{},
	}

	switch tt {
	case _TokenComment, _TokenString:
		tk.value = _TokenValue{vString: value.(string), vType: _TokenValueString}
	case _TokenBoolean:
		tk.value = _TokenValue{vBool: value.(bool), vType: _TokenValueBool}
	case _TokenNumber, _TokenIndent:
		tk.value = _TokenValue{vInt: value.(int), vType: _TokenValueInt}
	}

	tk.value.valid = true

	if tt == _TokenInvalid {
		panic(1)
	}

	t.tokens = append(t.tokens, tk)
}

func (t *_Tokenizer) tokenize(input string) error {
	for len(input) > 0 {
		var chop = 0
		switch {
		case input[0] == '\n' || input[0] == '\r':
			chop++
			if len(input) > 1 && input[1] == '\n' {
				chop++
			}
			t.line++
			t.col = 0
			t.buildToken(_TokenNewLine, nil)
		case input[0] == '#':
			chop++
			nextNewLine := strings.Index(input[chop:], "\n")
			if nextNewLine == -1 {
				nextNewLine = len(input)
			}
			nextNewLine += chop
			val := input[chop:nextNewLine]
			chop = nextNewLine
			t.buildToken(_TokenComment, val)
		case input[0] == ' ':
			if t.lastNewLine {
				indentSize := 1
				for i := 1; input[i] == ' '; i++ {
					indentSize++
				}
				if indentSize%2 == 1 {
					return errors.New("Invalid number of spaces")
				}
				chop = indentSize
				t.buildToken(_TokenIndent, indentSize/2)
			} else {
				chop++
			}
		case input[0] == '"':
			i := 1
			for ; i < len(input); i++ {
				if input[i] == '"' {
					isEscaped := input[i-1] == '\\' && input[i-2] != '\\'
					if !isEscaped {
						i++
						break
					}
				}
			}
			val := input[:i]
			chop = i
			var s string
			if e := json.Unmarshal([]byte(val), &s); e != nil {
				t.buildToken(_TokenInvalid, nil)
			} else {
				t.buildToken(_TokenString, s)
			}
		case input[0] >= '0' && input[0] <= '9':
			val := _numberPattern.FindString(input)
			chop = len(val)
			n, _ := strconv.Atoi(val)
			t.buildToken(_TokenNumber, n)
		case strings.HasPrefix(input, "true"):
			t.buildToken(_TokenBoolean, true)
			chop = 4
		case strings.HasSuffix(input, "false"):
			t.buildToken(_TokenBoolean, false)
			chop = 5
		case input[0] == ':':
			t.buildToken(_TokenColon, nil)
			chop++
		case input[0] == ',':
			t.buildToken(_TokenComma, nil)
			chop++
		case _strPattern.MatchString(input):
			i := 0
			for ; i < len(input); i++ {
				char := input[i]
				if char == ':' || char == ' ' || char == '\r' || char == '\n' || char == ',' {
					break
				}
			}
			name := input[:i]
			chop = i
			t.buildToken(_TokenString, name)
		default:
			t.buildToken(_TokenInvalid, nil)
		}
		if chop == 0 {
			t.buildToken(_TokenInvalid, nil)
		}
		t.col += chop
		t.lastNewLine = input[0] == '\n' || (input[0] == '\r' && input[1] == '\n')
		if chop == 0 {
			panic("chop is zero")
		}
		input = input[chop:]
	}
	t.buildToken(_TokenEOF, nil)
	return nil
}

var _numberPattern = regexp.MustCompile(`^\d+`)
var _strPattern = regexp.MustCompile(`^[a-zA-Z\\/.-]`)
var _versionRegex = regexp.MustCompile(`^yarn lockfile v(\d+)$`)

const LockfileVersion = 1

type _Parser struct {
	fileLoc  string
	token    _Token
	tokens   []_Token
	tokenPtr int
	comments []string
}

func (p *_Parser) onComment(token _Token) {
	if !token.isString() {
		panic("expected token value to be a string")
	}
	comment := strings.TrimSpace(token.value.vString)

	versionMatch := _versionRegex.FindStringSubmatch(comment)
	if len(versionMatch) > 0 {
		version, _ := strconv.Atoi(versionMatch[1])
		if version > LockfileVersion {
			panic(fmt.Sprintf("Can't install from a lockfile of version %d as you're on an old yarn version that only supports versions up to %d. Run \\`$ yarn self-update\\` to upgrade to the latest version.", version, LockfileVersion))
		}
	}
	p.comments = append(p.comments, comment)
}

func (p *_Parser) next() _Token {
	if p.tokenPtr >= len(p.tokens) {
		panic("No more tokens")
	}
	tk := p.tokens[p.tokenPtr]
	p.tokenPtr++
	if tk.kind == _TokenComment {
		p.onComment(tk)
		return p.next()
	}
	p.token = tk
	return tk
}

func (p *_Parser) unexpected(msg string) {
	if msg == "" {
		panic("Unexpected token")
	} else {
		panic(fmt.Sprintf("%s%d:%d in %s", msg, p.token.line, p.token.col, p.fileLoc))
	}
}

func (p *_Parser) parse(indent int) interface{} {
	obj := map[_TokenValue]interface{}{}
	for {
		propToken := p.token
		if propToken.kind == _TokenNewLine {
			nextToken := p.next()
			if indent == 0 {
				// if we have 0 indentation then the next token doesn't matter
				continue
			}
			if nextToken.kind != _TokenIndent {
				// if we have no indentation after a newline then we've gone down a level
				break
			}
			if nextToken.value.vInt == indent {
				// all is good, the indent is on our level
				p.next()
			} else {
				// the indentation is less than our level
				break
			}
		} else if propToken.kind == _TokenIndent {
			if propToken.value.vInt == indent {
				p.next()
			} else {
				break
			}
		} else if propToken.kind == _TokenEOF {
			break
		} else if propToken.kind == _TokenString {
			// property key
			key := propToken.value
			if key.IsEmpty() {
				panic("Expected a key")
			}
			keys := []_TokenValue{key}
			p.next()
			// support multiple keys
			for p.token.kind == _TokenComma {
				p.next() // skip comma

				keyToken := p.token
				if keyToken.kind != _TokenString {
					p.unexpected("Expected string")
				}

				key := keyToken.value
				if key.IsEmpty() {
					panic("Expected a key")
				}
				keys = append(keys, key)
				p.next()
			}
			wasColon := p.token.kind == _TokenColon
			if wasColon {
				p.next()
			}
			if isValidPropValueToken(p.token) {
				for _, key := range keys {
					obj[key] = p.token.value // 299
				}
				p.next()
			} else if wasColon {
				val := p.parse(indent + 1)
				for _, key := range keys {
					obj[key] = val
				}
				if indent != 0 && p.token.kind != _TokenIndent {
					break
				}
			} else {
				p.unexpected("Invalid value type")
			}
		} else {
			p.unexpected(fmt.Sprintf("Unknown token: %v", propToken))
		}
	}
	return obj
}

func isValidPropValueToken(token _Token) bool {
	return token.kind == _TokenBoolean || token.kind == _TokenString || token.kind == _TokenNumber
}

type _ParseErr string

func (t _ParseErr) Error() string {
	return fmt.Sprintf("ParseError: %s", string(t))
}

func ParseLockFileData(data []byte) (lf schemas.YarnV1LockFile, err error) {
	defer func() {
		if e := recover(); e != nil {
			switch v := e.(type) {
			case error:
				err = v
			case string:
				err = _ParseErr(v)
			case fmt.Stringer:
				err = _ParseErr(v.String())
			default:
				err = _ParseErr("Unknown err")
			}
		}
	}()

	tokenizer := _Tokenizer{}
	if err = tokenizer.tokenize(string(data)); err != nil {
		return nil, err
	}

	parser := _Parser{
		tokens: tokenizer.tokens,
	}
	parser.next()

	data, err = json.Marshal(parser.parse(0))
	if err != nil {
		return nil, errors.Wrap(err, "parse failed")
	}

	if err = json.Unmarshal(data, &lf); err != nil {
		return nil, errors.Wrap(err, "parse failed")
	}

	return
}

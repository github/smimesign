package main

import "strings"

// The following was copied from the crypto/openpgpg/packet package.

// The original license can be found at
// https://github.com/golang/crypto/blob/9f005a07e0d31d45e6656d241bb5c0f2efd4bc94/LICENSE
//
//     Copyright (c) 2009 The Go Authors. All rights reserved.
//
//     Redistribution and use in source and binary forms, with or without
//     modification, are permitted provided that the following conditions are
//     met:
//
//        * Redistributions of source code must retain the above copyright
//     notice, this list of conditions and the following disclaimer.
//        * Redistributions in binary form must reproduce the above
//     copyright notice, this list of conditions and the following disclaimer
//     in the documentation and/or other materials provided with the
//     distribution.
//        * Neither the name of Google Inc. nor the names of its
//     contributors may be used to endorse or promote products derived from
//     this software without specific prior written permission.
//
//     THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
//     "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
//     LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
//     A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
//     OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
//     SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
//     LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
//     DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
//     THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
//     (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
//     OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

// The orignal code can be found at
// https://github.com/golang/crypto/blob/9f005a07e0d31d45e6656d241bb5c0f2efd4bc94/openpgp/packet/userid.go#L89-L160
//
// parseUserID extracts the name, comment and email from a user id string that
// is formatted as "Full Name (Comment) <email@example.com>".
func parseUserID(id string) (name, comment, email string) {
	var n, c, e struct {
		start, end int
	}
	var state int

	for offset, rune := range id {
		switch state {
		case 0:
			// Entering name
			n.start = offset
			state = 1
			fallthrough
		case 1:
			// In name
			if rune == '(' {
				state = 2
				n.end = offset
			} else if rune == '<' {
				state = 5
				n.end = offset
			}
		case 2:
			// Entering comment
			c.start = offset
			state = 3
			fallthrough
		case 3:
			// In comment
			if rune == ')' {
				state = 4
				c.end = offset
			}
		case 4:
			// Between comment and email
			if rune == '<' {
				state = 5
			}
		case 5:
			// Entering email
			e.start = offset
			state = 6
			fallthrough
		case 6:
			// In email
			if rune == '>' {
				state = 7
				e.end = offset
			}
		default:
			// After email
		}
	}
	switch state {
	case 1:
		// ended in the name
		n.end = len(id)
	case 3:
		// ended in comment
		c.end = len(id)
	case 6:
		// ended in email
		e.end = len(id)
	}

	name = strings.TrimSpace(id[n.start:n.end])
	comment = strings.TrimSpace(id[c.start:c.end])
	email = strings.TrimSpace(id[e.start:e.end])
	return
}

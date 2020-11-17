module main

import jwt

fn test_encode() {
	payload := {
		'sub': '1234567890'
		'name': 'John Doe'
		'iat': '1516239022'
	}
	token := jwt.encode({
		payload: payload
		key: 'secret'
		algorithm: 'HS512'
	})
	assert token == 'eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoiMTUxNjIzOTAyMiJ9.hMl9ZgnOmzvvtIRsySeavSKFdEdpINPr2IVqcVRU-BONFDpk2MakIS-0vKTTsRPYKiQR7WpsDX1iU0MGjBEB5Q'
}

/*
fn test_decode() {
	token := ''
	obj := jwt.decode({
		token: token
		key: 'secret'
		algorithm: 'HS512'
	}) or { json2.Any{} }
	// assert obj == ''
}
*/

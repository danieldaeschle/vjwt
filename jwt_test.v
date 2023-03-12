module jwt

import jwt
import x.json2

fn test_encode_map_hs256() {
	payload := {
		'sub':  json2.Any('1234567890')
		'name': 'John Doe'
		'iat':  '1516239022'
	}
	token := jwt.encode(
		payload: payload
		key: 'secret'
	)!
	assert token == 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoiMTUxNjIzOTAyMiJ9.1pGITVN1_HkzPxvMfRvTNEmJSiCSUZ_YVWhRt4AmYYw'
}

fn test_encode_map_hs512() {
	mut payload := map[string]json2.Any{}
	payload['sub'] = '1234567890'
	payload['name'] = 'John Doe'
	payload['iat'] = '1516239022'

	token := jwt.encode(
		payload: payload
		key: 'secret'
		algorithm: .hs512
	)!
	assert token == 'eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoiMTUxNjIzOTAyMiJ9.hMl9ZgnOmzvvtIRsySeavSKFdEdpINPr2IVqcVRU-BONFDpk2MakIS-0vKTTsRPYKiQR7WpsDX1iU0MGjBEB5Q'
}

fn test_verify_hs256_true() {
	assert jwt.verify(
		token: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoiMTUxNjIzOTAyMiJ9.1pGITVN1_HkzPxvMfRvTNEmJSiCSUZ_YVWhRt4AmYYw'
		key: 'secret'
	)
}

fn test_verify_hs512_true() {
	assert jwt.verify(
		token: 'eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoiMTUxNjIzOTAyMiJ9.hMl9ZgnOmzvvtIRsySeavSKFdEdpINPr2IVqcVRU-BONFDpk2MakIS-0vKTTsRPYKiQR7WpsDX1iU0MGjBEB5Q'
		key: 'secret'
		algorithm: .hs512
	)
}

struct DecodeHS256ToStructResult {
	sub  string
	name string
	iat  string
}

fn test_decode_hs256_to_struct() {
	token := 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoiMTUxNjIzOTAyMiJ9.1pGITVN1_HkzPxvMfRvTNEmJSiCSUZ_YVWhRt4AmYYw'

	obj := jwt.decode[DecodeHS256ToStructResult](
		token: token
		key: 'secret'
	)!

	assert obj == DecodeHS256ToStructResult{
		sub: '1234567890'
		name: 'John Doe'
		iat: '1516239022'
	}
}

module main

import x.json2
import json
import encoding.base64
import crypto.sha256
import crypto.sha512
import crypto.hmac

const (
	algorithms  = {
		'HS256': sha256.sum
		'HS512': sha512.sum512
		'HS384': sha512.sum384
	}
	block_sizes = {
		'HS256': sha256.block_size
		'HS512': sha512.block_size
		'HS384': sha512.block_size
	}
)

pub struct JwtClaims {
	iss string
	sub string
	aud string
	exp int
	nbf int
	iat int
	jti string
}

struct JoseHeader {
pub mut:
	cty string
	alg string
	typ string = 'JWT'
}

pub fn (h JoseHeader) to_json() string {
	mut obj := map[string]json2.Any{}
	if h.cty != '' {
		obj['cty'] = h.cty
	}
	obj['alg'] = h.alg
	obj['typ'] = h.typ
	return obj.str()
}

pub struct EncodeOptions {
	payload   map[string]string
	key       string
	algorithm string = 'HS256'
}

pub fn encode(options EncodeOptions) string {
	mut headers := JoseHeader{
		alg: options.algorithm
	}
	json_header := json2.encode<JoseHeader>(headers)
	json_payload := json.encode(options.payload)
	mut segments := []string{}
	segments << base64.encode_url(json_header)
	segments << base64.encode_url(json_payload)
	signing_input := segments.join('.')
	if options.algorithm !in algorithms {
		panic('algorithm $options.algorithm is not supported, fallback to HS256')
	}
	hash_fn := algorithms[options.algorithm]
	block_size := block_sizes[options.algorithm]
	signature := hmac.new(options.key.bytes(), signing_input.bytes(), hash_fn, block_size)
	segments << base64.encode_url(signature.bytestr())
	return segments.join('.')
}

pub struct DecodeOptions {
	jwt       string
	key       string
	algorithm string = 'HS256'
	verify    bool   = true
}

pub fn decode<T>(options DecodeOptions) ?T {
	split_jwt := options.jwt.split('.')
	signing_input := '${split_jwt[0]}.${split_jwt[1]}'
	header_segment := split_jwt[0]
	payload_segment := split_jwt[1]
	crypto_segment := split_jwt[2]
	header_data := base64.decode_url(header_segment)
	return none
}

fn main() {
	payload := {
		'sub': '1234567890'
		'name': 'John Doe'
		'iat': '1516239022'
	}
	s := encode({
		payload: payload
		key: 'secret'
		algorithm: 'HS512'
	})
	println(s)
}

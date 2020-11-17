module jwt

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

pub struct JWT {
	algorithm string
}

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
	jwt := JWT{
		algorithm: options.algorithm
	}
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
		panic('algorithm $options.algorithm is not supported')
	}
	segments << jwt.sign(signing_input, options.key)
	return segments.join('.')
}

fn (jwt JWT) sign(message string, key string) string {
	hash_fn := algorithms[jwt.algorithm]
	block_size := block_sizes[jwt.algorithm]
	signature := hmac.new(key.bytes(), message.bytes(), hash_fn, block_size)
	return base64.encode_url(signature.bytestr())
}

fn (jwt JWT) verify(message string, key string, signature string) bool {
	return jwt.sign(message, key) == signature
}

pub struct DecodeOptions {
	token     string
	key       string
	algorithm string = 'HS256'
	verify    bool   = true
}

pub fn decode(options DecodeOptions) ?json2.Any {
	jwt := JWT{
		algorithm: options.algorithm
	}
	split_token := options.token.split('.')
	signing_input := '${split_token[0]}.${split_token[1]}'
	signature := split_token[2]
	if options.verify {
		if !jwt.verify(signing_input, options.key, signature) {
			return none
		}
	}
	// header_segment := split_jwt[0]
	payload_segment := split_token[1]
	payload_data := base64.decode_url(payload_segment)
	payload := json2.raw_decode(payload_data)?
	return payload
}

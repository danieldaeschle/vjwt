module jwt

import x.json2
import encoding.base64
import crypto.sha256
import crypto.sha512
import crypto.hmac

const (
	algorithms = {
		Algorithm.hs256: sha256.sum
		Algorithm.hs384: sha512.sum384
		Algorithm.hs512: sha512.sum512
	}
	block_sizes = {
		Algorithm.hs256: sha256.block_size
		Algorithm.hs384: sha512.block_size
		Algorithm.hs512: sha512.block_size
	}
)

pub enum Algorithm {
	hs256
	hs384
	hs512
}

pub fn (a Algorithm) str() string {
	return match a {
		.hs256 {
			'HS256'
		}
		.hs384 {
			'HS384'
		}
		.hs512 {
			'HS512'
		}
	}
}

pub struct JWT {
	algorithm Algorithm
	key       string
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

fn (j JWT) sign(message string) string {
	hash_fn := jwt.algorithms[j.algorithm]
	block_size := jwt.block_sizes[j.algorithm]
	signature := hmac.new(j.key.bytes(), message.bytes(), hash_fn, block_size)
	url_encoded := base64.url_encode_str(signature.bytestr())
	return url_encoded
}

fn (j JWT) verify(token string) bool {
	split_token := token.split('.')
	signing_input := split_token[..2].join('.')
	signature := split_token[2]
	return j.sign(signing_input) == signature
}

pub struct EncodeOptions[T] {
	payload   T
	key       string
	algorithm Algorithm = .hs256
	headers   map[string]json2.Any
}

pub fn encode[T](options EncodeOptions[T]) !string {
	if options.algorithm !in jwt.algorithms {
		return error('algorithm ${options.algorithm} is not supported')
	}
	jwt := JWT{
		algorithm: options.algorithm
		key: options.key
	}
	mut headers := options.headers.clone()
	headers['alg'] = options.algorithm.str()
	headers['typ'] = 'JWT'
	json_header := json2.encode(headers)
	json_payload := json2.encode(options.payload)
	mut segments := [base64.url_encode_str(json_header), base64.url_encode_str(json_payload)]
	signing_input := segments.join('.')
	segments << jwt.sign(signing_input)
	return segments.join('.')
}

pub struct DecodeOptions {
	token     string
	key       string
	algorithm Algorithm = .hs256
	verify    bool      = true
}

pub fn decode[T](options DecodeOptions) !T {
	jwt := JWT{
		algorithm: options.algorithm
		key: options.key
	}
	split_token := options.token.split('.')
	if options.verify {
		if !jwt.verify(options.token) {
			return error('invalid signature')
		}
	}

	payload_segment := split_token[1]
	payload_data := base64.decode_str(payload_segment)
	payload := json2.decode[T](payload_data)!
	return payload
}

pub struct VerifyOptions {
	token     string
	key       string
	algorithm Algorithm = .hs256
}

pub fn verify(options VerifyOptions) bool {
	jwt := JWT{
		algorithm: options.algorithm
		key: options.key
	}
	return jwt.verify(options.token)
}

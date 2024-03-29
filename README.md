> Currently it's work in progress until the json module in V is finalized.
# jwt for V
A small native library to encode and decode JWT in V.

# Getting started

## Encode
To parse a struct to a JWT token you just have to do:
> This example is using a `map[string]string` as payload.
```v
import jwt

payload := {
    'sub': '1234567890'
    'name': 'John Doe'
    'iat': '1516239022'
}
token := jwt.encode(
	payload: payload
	key: 'secret'
)!
```

## Decode

```v
import jwt
    
struct User {
   name string
}
    
obj := jwt.decode[User](
	payload: payload
	key: 'secret'
)!
```


# Implementation progress
- [x] Sign
- [x] Verify
- [x] HS256
- [x] HS384
- [x] HS512
- [ ] PS256
- [ ] PS384
- [ ] PS512
- [ ] RS256
- [ ] RS384
- [ ] RS512
- [ ] ES256
- [ ] ES256K
- [ ] ES384
- [ ] ES512
- [ ] EdDSA
- [ ] `iss` check
- [ ] `sub` check
- [ ] `aud` check
- [ ] `exp` check
- [ ] `nbf` check
- [ ] `iat` check
- [ ] `jti` check

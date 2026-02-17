# ngx-http-set_json-module

A nginx module to issue JSON Web Tokens (JWT) putting them into standard nginx variable

### Example configuration:

```
    set_jwt_key "your_very_secure_secret_key";
    #set_jwt_key_file /etc/nginx/jwt_key1;
    set_jwt_algorithm "HS256";          # default value HS256
    set_jwt_expires 3600;               # if not set an exp claim will not be added
    set_jwt $jwt '{"iss":"$host","sub":"$ssl_client_s_dn"}'; # json to make JWT from

    proxy_set_header Authorization "Bearer $jwt";
    proxy_pass https://upstream;
```

## Directives

### set_jwt

| | |
| --- | --- |
| **Syntax**  | **set_jwt** $variable string |
| **Default** | none |
| **Context** | server, location |

Enable producing `$variable` containg JWT from JSON string.
The `string` can contain variables. Example above.

| | |
| --- | --- |
| **Syntax**  | **set_jwt_algorithm** none \| HS256 \| HS384 \| HS512 \| RS256 \| RS384 \| RS512 \| ES256 \| ES384 \| ES512 |
| **Default** | HS256 |
| **Context** | server, location |

Define alorithm for output JWT

| | |
| --- | --- |
| **Syntax**  | **set_jwt_expires** seconds |
| **Default** | none |
| **Context** | server, location |

Set expires time of the token.
`iat` claim (issued at time) is always the current time of request,
`exp` claim (expiration time) is computed as a sum of the current time and provided `seconds`. If no value defined or 0, an `exp` claim will not be added to token.

| | |
| --- | --- |
| **Syntax**  | **set_jwt_key** string |
| **Default** | "" |
| **Context** | server, location |

Set a key to sign the output token.

| | |
| --- | --- |
| **Syntax**  | **set_jwt_key_file** filename |
| **Default** | none |
| **Context** | server, location |

Set the filename containing a key to sign the output token.
A key can be simple string for symmetric signing (HS) or private key for asymmetric (RS/ES) signing.

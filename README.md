# rust-cfzt-validator

This crate provides the basic machinery required to build apps that can integrate with Cloudflare Zero Trust by validating and inspecting Application Token JWTs.

Specifically, this crate provides the following:
 - Parsing/retrieval of signing keys from the Cloudflare Zero Trust API
 - Lazy construction and caching of the `jsonwebtoken::DecodingKey` structs derived fromt the signing keys
 - Configurable validation of Application Tokens for one or multiple Zero Trust teams
 - Optional convenience struct for validated claims
 - Support for periodic refreshes of the Cloudflare Zero Trust signing keys

By design, this crate does not provide the following:
 - Machinery for retrieving the [User Identity](https://developers.cloudflare.com/cloudflare-one/identity/authorization-cookie/application-token/#user-identity) data associated with a token.
 - Opinionated patterns for integration into async runtimes

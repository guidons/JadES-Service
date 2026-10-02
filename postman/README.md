# Postman Collection

Import `JAdES Signing Service.postman_collection.json` into Postman using **Import > Files**. It contains requests for health, OAuth client credentials, CSC v2 hash authorization, and signing, with one saved example per request.

## Mock the API

1. Create a mock server from the imported collection and select its saved examples.
2. Copy the mock server URL. In each request, replace `http://127.0.0.1:8000` with that URL, keeping the path unchanged.
3. Send any request. Mock responses do not require a running service or credentials.

The mock responses demonstrate the API shapes only. In particular, the mock signature is a placeholder and is not cryptographically valid. No running service or credentials are needed when using the mock server.

## Call a local service

Start the API using the instructions in the project README, then send the requests in order: token, authorize hash, sign hash. The collection saves the returned access token and SAD and supplies them to subsequent requests. The default client credentials match the development defaults; change the form fields if using other credentials.

The sample digest is SHA-256 of `hello world`, Base64-encoded as required by CSC. The mock signature is illustrative and is not cryptographically valid.

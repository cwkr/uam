package main

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"html/template"
	"math/rand"
	"net/http"
)

func Index(w http.ResponseWriter, r *http.Request) {
	const tpl = `<!doctype html>
<h1>Jwtoker</h1>
<a href="jwks.json">jwks.json</a>
<br>
<br>
<pre>
{{.public_key}}
</pre>
<br>
<a href="http://localhost:{{.port}}/auth?response_type=token&client_id=joker&redirect_uri=http%3A%2F%2Flocalhost%3A{{.port}}%2F&state={{.state}}">Get token</a><br>
<pre style="white-space: pre-wrap; max-width: 40em; word-wrap: break-word;">
<script>
var hash = window.location.hash.substr(1);

var hash_params = hash.split('&').reduce(function (result, item) {
    var parts = item.split('=');
    result[parts[0]] = parts[1];
    return result;
}, {});

if (hash_params.access_token) {
	document.write(hash_params.access_token);
}
</script>
</pre>`
	t, _ := template.New("index").Parse(tpl)

	pubASN1, err := x509.MarshalPKIXPublicKey(&rsaPrivKey.PublicKey)
	if err != nil {
		// do something about it
	}

	pubBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: pubASN1,
	})

	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
	t.Execute(w, map[string]string{
		"public_key": string(pubBytes),
		"port": fmt.Sprint(config.Port),
		"state": fmt.Sprint(rand.Int()),
	})
}

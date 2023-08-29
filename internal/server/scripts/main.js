import * as jwt from './jwt.js';

function rememberRequestForm() {
    const clientId = document.getElementById("client_id").value;
    const responseType = document.getElementById("response_type").value;
    const scope = document.getElementById("scope").value;
    const codeVerifier = document.getElementById("code_verifier").value;
    sessionStorage.setItem("client_id", clientId);
    sessionStorage.setItem("response_type", responseType);
    sessionStorage.setItem("scope", scope);
    if (responseType === "code") {
        sessionStorage.setItem('code_verifier', codeVerifier);
    }
}

function rememberRevokeForm() {
    const clientId = document.getElementById("revoke_client_id").value;
    const tokenTypeHint = document.getElementById("token_type_hint").value;
    sessionStorage.setItem("client_id", clientId);
    sessionStorage.setItem("token_type_hint", tokenTypeHint);
}

function updateFields(responseType) {
    if (responseType === "code") {
        document.querySelectorAll("#code_challenge, #code_challenge_method, #nonce, #scope").forEach(input => {
            input.disabled = false;
        });
        document.querySelectorAll("#client_secret, #username, #password").forEach(input => {
            input.disabled = true;
        });
    } else if (responseType === "token") {
        document.querySelectorAll("#code_challenge, #code_challenge_method, #nonce, #client_secret, #username, #password").forEach(input => {
            input.disabled = true;
        });
        document.querySelectorAll("#scope").forEach(input => {
            input.disabled = false;
        });
    } else if (responseType === "client_credentials") {
        document.querySelectorAll("#code_challenge, #code_challenge_method, #nonce, #username, #password").forEach(input => {
            input.disabled = true;
        });
        document.querySelectorAll("#scope, #client_secret").forEach(input => {
            input.disabled = false;
        });
    } else if (responseType === "password") {
        document.querySelectorAll("#code_challenge, #code_challenge_method, #nonce, #username, #password").forEach(input => {
            input.disabled = true;
        });
        document.querySelectorAll("#username, #password, #scope, #client_secret").forEach(input => {
            input.disabled = false;
        });
    }
}

function onResponseTypeChange(event) {
    updateFields(event.target.value);
}

function getToken(params) {
    const postParams = new URLSearchParams(params);
    fetch("token", {method: "POST", body: postParams})
        .then(async resp => {
            if (!resp.ok) {
                throw new Error(await resp.text());
            }
            return resp.json();
        })
        .then(data => {
            if (data.access_token) {
                document.getElementById("access_token_output").textContent = data.access_token;
                document.getElementById("access_token_json").textContent = JSON.stringify(jwt.decode(data.access_token), null, 2);
                document.getElementById("access_token_panel").style.display = 'block';
                document.getElementById("refresh_token_panel").style.display = 'none';
                document.getElementById("id_token_panel").style.display = 'none';
            }
        })
        .catch(error => {
            console.error(error);
            document.getElementById("access_token_output").textContent = error.message;
            document.getElementById("access_token_json").textContent = '';
            document.getElementById("access_token_panel").style.display = 'block';
            document.getElementById("refresh_token_panel").style.display = 'none';
            document.getElementById("id_token_panel").style.display = 'none';
        });
}

function onRequestFormSubmit(event) {
    const checkedScopes = document.querySelectorAll('input[id^="scope_"]:checked');
    document.getElementById("scope").value = Array.from(checkedScopes).map(input => input.value).join(' ');

    const responseType = document.getElementById("response_type").value;
    if (responseType === 'client_credentials') {
        event.preventDefault();
        getToken({
            "grant_type": "client_credentials",
            "client_id": document.getElementById("client_id").value,
            "client_secret": document.getElementById("client_secret").value,
            "scope": document.getElementById("scope").value
        });
    } else if (responseType === 'password') {
        event.preventDefault();
        getToken({
            "grant_type": "password",
            "client_id": document.getElementById("client_id").value,
            "client_secret": document.getElementById("client_secret").value,
            "username": document.getElementById("username").value,
            "password": document.getElementById("password").value,
            "scope": document.getElementById("scope").value
        });
    }

    rememberRequestForm();
}

function onRevokeFormSubmit(event) {
    event.preventDefault();
    const postParams = new URLSearchParams({
        "token_type_hint": document.getElementById("token_type_hint").value,
        "client_id": document.getElementById("revoke_client_id").value,
        "client_secret": document.getElementById("revoke_client_secret").value,
        "token": document.getElementById("revoke_token").value,
    });
    fetch("revoke", {method: "POST", body: postParams})
        .then(async resp => {
            if (!resp.ok) {
                throw new Error(await resp.text());
            }
            return resp.text();
        })
        .then(data => {
            document.getElementById("revoke_token").value = '';
        })
        .catch(error => {
            console.error(error);
            document.getElementById("revoke_token").value = error.message;
        });

    rememberRevokeForm();
}

document.getElementById('response_type').addEventListener("change", onResponseTypeChange);
document.getElementById('request_form').addEventListener("submit", onRequestFormSubmit);
document.getElementById('revoke_form').addEventListener("submit", onRevokeFormSubmit);
document.addEventListener('DOMContentLoaded', () => {
    if (document.readyState === 'loading') {
        return;
    }

    const rememberedResponseType = sessionStorage.getItem("response_type");
    if (rememberedResponseType) {
        document.getElementById("response_type").value = rememberedResponseType;
        updateFields(rememberedResponseType);
    }

    const rememberedClientId = sessionStorage.getItem("client_id");
    if (rememberedClientId) {
        document.getElementById("client_id").value = rememberedClientId;
        document.getElementById("client_id_logout").value = rememberedClientId;
        document.getElementById("revoke_client_id").value = rememberedClientId;
    }

    const rememberedScope = sessionStorage.getItem("scope");
    if (rememberedScope) {
        const rememberedScopes = rememberedScope.split(/\s+/g);
        document.getElementById("scope").value = rememberedScope;
        document.querySelectorAll('input[id^="scope_"]').forEach(input => {
            console.log(input);
            input.checked = rememberedScopes.includes(input.value);
        });
    }

    const rememberedTokenTypeHint = sessionStorage.getItem("token_type_hint");
    if (rememberedTokenTypeHint) {
        document.getElementById("token_type_hint").value = rememberedTokenTypeHint;
        updateFields(rememberedTokenTypeHint);
    }

    let urlParams = new URLSearchParams();
    const hash = window.location.hash.substring(1);
    if (hash) {
        urlParams = new URLSearchParams(hash);
    } else if (window.location.search) {
        urlParams = new URLSearchParams(window.location.search);
    }
    if (urlParams.has("access_token") === true) {
        const accessToken = urlParams.get("access_token");
        document.getElementById("access_token_output").textContent = accessToken;
        document.getElementById("access_token_json").textContent = JSON.stringify(jwt.decode(accessToken), null, 2);
        document.getElementById("access_token_panel").style.display = 'block';
    } else if (urlParams.has("code") === true) {
        const postParams = new URLSearchParams({
            "grant_type": "authorization_code",
            "code": urlParams.get("code"),
            "client_id": sessionStorage.getItem('client_id'),
            "code_verifier": sessionStorage.getItem('code_verifier')
        });
        fetch("token", {method: "POST", body: postParams})
            .then(async resp => {
                if (!resp.ok) {
                    throw new Error(await resp.text());
                }
                return resp.json();
            })
            .then(data => {
                if (data.access_token) {
                    document.getElementById("access_token_output").textContent = data.access_token;
                    document.getElementById("access_token_json").textContent = JSON.stringify(jwt.decode(data.access_token), null, 2);
                    document.getElementById("access_token_panel").style.display = 'block';
                }
                if (data.refresh_token) {
                    document.getElementById("refresh_token_output").textContent = data.refresh_token;
                    document.getElementById("refresh_token_panel").style.display = 'block';
                    document.getElementById("revoke_token").value = data.refresh_token;
                }
                if (data.id_token) {
                    document.getElementById("id_token_output").textContent = data.id_token;
                    document.getElementById("id_token_json").textContent = JSON.stringify(jwt.decode(data.id_token), null, 2);
                    document.getElementById("id_token_panel").style.display = 'block';
                }
            })
            .catch(error => {
                console.error(error);
                document.getElementById("access_token_output").textContent = error.message;
                document.getElementById("access_token_json").textContent = '';
                document.getElementById("access_token_panel").style.display = 'block';
                document.getElementById("refresh_token_panel").style.display = 'none';
                document.getElementById("id_token_json").textContent = '';
                document.getElementById("id_token_panel").style.display = 'none';
            });
    }
});

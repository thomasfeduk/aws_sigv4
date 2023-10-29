class AWSSigner {
    constructor(access_key, secret_key, session_token, region, service) {
        this.access_key = access_key;
        this.secret_key = secret_key;
        this.session_token = session_token;
        this.region = region;
        this.service = service;
    }

    static sign(key, message) {
        if (typeof key === "string") {
            key = CryptoJS.enc.Utf8.parse(key);
        }
        let messageWordArray = CryptoJS.enc.Utf8.parse(message);
        return CryptoJS.HmacSHA256(messageWordArray, key);
    }

    get_signature_key(date_stamp) {
        let k_date = AWSSigner.sign(CryptoJS.enc.Utf8.parse("AWS4" + this.secret_key), date_stamp);
        let k_region = AWSSigner.sign(k_date, this.region);
        let k_service = AWSSigner.sign(k_region, this.service);
        let k_signing = AWSSigner.sign(k_service, "aws4_request");
        return k_signing;
    }

    create_canonical_request(method, uri, querystring, headers, payload) {
        let signed_headers_list = Object.keys(headers).map(h => h.toLowerCase()).sort();
        let signed_headers = signed_headers_list.join(';');
        let payload_hash = CryptoJS.SHA256(payload).toString(CryptoJS.enc.Hex);
        let canonical_headers = Object.entries(headers).sort(([a], [b]) => a.toLowerCase().localeCompare(b.toLowerCase())).map(([key, value]) => `${key}:${value}\n`).join('');
        return `${method}\n${uri}\n${querystring}\n${canonical_headers}\n${signed_headers}\n${payload_hash}`;
    }

    get_string_to_sign(amz_date, date_stamp, canonical_request) {
        let credential_scope = `${date_stamp}/${this.region}/${this.service}/aws4_request`;
        let string_to_sign = `AWS4-HMAC-SHA256\n${amz_date}\n${credential_scope}\n${CryptoJS.SHA256(canonical_request).toString(CryptoJS.enc.Hex)}`;
        return [string_to_sign, credential_scope];
    }

    get_authorization_header(amz_date, date_stamp, canonical_request) {
        let [string_to_sign, credential_scope] = this.get_string_to_sign(amz_date, date_stamp, canonical_request);
        let signing_key = this.get_signature_key(date_stamp);
        let signature = AWSSigner.sign(signing_key, string_to_sign);
        return `AWS4-HMAC-SHA256 Credential=${this.access_key}/${credential_scope}, SignedHeaders=host;x-amz-date;x-amz-security-token, Signature=${signature}`;
    }
}

class AWSLambdaClient {
    constructor(signer) {
        this.signer = signer;
        this.endpoint = `https://lambda.${signer.region}.amazonaws.com/2015-03-31`;
        this.host = `lambda.${signer.region}.amazonaws.com`;
    }

    _get_headers({ method, uri, payload = "", headers_additional = null }) {
        let t = new Date();
        // Debugging
        // var specificDateStr = "2023-09-18T00:21:37.356Z"; // 'Z' indicates it's UTC
        // var t = new Date(specificDateStr);
        let amz_date = t.toISOString().replace(/[:-]|\.\d{3}/g, "");
        let date_stamp = t.toISOString().split('T')[0].replace(/-/g, "");

        let headers = {
            'host': this.host,
            'x-amz-date': amz_date,
            'x-amz-security-token': ''
        };

        // Add session token if available
        if (this.signer.session_token) {
            headers['x-amz-security-token'] = this.signer.session_token;
        }

        let canonical_request = this.signer.create_canonical_request(method, uri, "", headers, payload);
        headers["Authorization"] = this.signer.get_authorization_header(amz_date, date_stamp, canonical_request);
        delete headers["host"];

        if (!this.signer.session_token) {
            delete headers["x-amz-security-token"];
        }
        // Inject the additional headers if passed outside of the authorization signing process
        if (headers_additional) {
            Object.assign(headers, headers_additional);
        }

        return headers;
    }

    lambda_list_functions(callback) {
        let method = "GET";
        let uri = "/2015-03-31/functions/";
        let headers = this._get_headers({method: method, uri: uri});

        const requestParams = {
            url: `${this.endpoint}/functions/`,
            method: method,
            header: headers,
            body: {
                mode: 'raw',
                raw: ''
            }
        };

        pm.sendRequest(requestParams, function (err, response) {
            if (err) {
                console.error('Error making HTTP call to AWS:', err);
            } else {
                callback(err, response)
            }
        });
    }

    lambda_invoke(function_name, payload, callback) {
        let method = "POST";
        let uri = `/2015-03-31/functions/${function_name}/invocations`;
        let payload_json = JSON.stringify(payload);
        let headers = this._get_headers({ method: method, uri: uri, payload: payload_json });

        let requestParams = {
            url: `${this.endpoint}/functions/${function_name}/invocations`,
            method: method,
            header: headers,
            body: {
                mode: 'raw',
                raw: payload_json
            }
        };

        pm.sendRequest(requestParams, function (err, response) {
            if (err) {
                console.error('Error making HTTP call to AWS:', err);
            } else {
                callback(err, response)
            }
        });
    }
}

// Usage in Postman pre-request script:
let signer = new AWSSigner(
    pm.environment.get("AWS-AccessKeyId"),
    pm.environment.get("AWS-SecretAccessKey"),
    pm.environment.get("AWS-SessionToken"),
    pm.environment.get("AWS-Region"),
    'lambda');

let client = new AWSLambdaClient(signer);

client.lambda_invoke(pm.environment.get("FunctionName"), JSON.parse(pm.environment.get("FunctionPayload")), (err, response) => {
    if (response) {
        console.log('Lambda Response: '+ response.code + ' ' + response.status);
        console.log(response.text());
    }
});
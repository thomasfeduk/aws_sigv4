import hashlib
import hmac
import datetime
import requests
import json
import base64


class AWSSigner:
    def __init__(self, aws_config: dict, service: str):
        self.access_key = aws_config['access_key']
        self.secret_key = aws_config['secret_key']
        self.session_token = aws_config['session_token']
        self.region = aws_config['region']
        self.service = service

    @staticmethod
    def sign(key, message):
        return hmac.new(key, message.encode('utf-8'), hashlib.sha256).digest()

    def get_signature_key(self, date_stamp):
        k_date = self.sign(("AWS4" + self.secret_key).encode('utf-8'), date_stamp)
        k_region = self.sign(k_date, self.region)
        k_service = self.sign(k_region, self.service)
        k_signing = self.sign(k_service, "aws4_request")
        return k_signing

    def create_canonical_request(self, method, uri, querystring, headers, payload):
        signed_headers_list = sorted([header.lower() for header in headers.keys()])
        signed_headers = ';'.join(signed_headers_list)
        payload_hash = hashlib.sha256(payload.encode('utf-8')).hexdigest()
        canonical_headers = ''.join(
            [f"{header}:{value}\n" for header, value in sorted(headers.items(), key=lambda x: x[0].lower())])
        canonical_request = f"{method}\n{uri}\n{querystring}\n{canonical_headers}\n{signed_headers}\n{payload_hash}"
        return canonical_request

    def get_string_to_sign(self, amz_date, date_stamp, canonical_request):
        credential_scope = f"{date_stamp}/{self.region}/{self.service}/aws4_request"
        string_to_sign = f"AWS4-HMAC-SHA256\n{amz_date}\n{credential_scope}\n{hashlib.sha256(canonical_request.encode('utf-8')).hexdigest()}"
        return string_to_sign, credential_scope

    def get_authorization_header(self, amz_date, date_stamp, canonical_request):
        string_to_sign, credential_scope = self.get_string_to_sign(amz_date, date_stamp, canonical_request)
        signing_key = self.get_signature_key(date_stamp)
        signature = hmac.new(signing_key, string_to_sign.encode('utf-8'), hashlib.sha256).hexdigest()
        authorization_header = f"AWS4-HMAC-SHA256 Credential={self.access_key}/{credential_scope}, " \
                               f"SignedHeaders=host;x-amz-date;x-amz-security-token, Signature={signature}"
        return authorization_header


class AWSClient:
    def __init__(self, aws_config: dict, service: str):
        self.signer = AWSSigner(aws_config, "lambda")
        self.endpoint = f"https://lambda.{aws_config['region']}.amazonaws.com/2015-03-31"
        self.host = f"lambda.{aws_config['region']}.amazonaws.com"

    def _get_headers(self, *, method, uri, payload="", headers_additional: dict | None = None):
        t = datetime.datetime.utcnow()
        # t = datetime.datetime.strptime("2023-09-18 00:21:37.356658", '%Y-%m-%d %H:%M:%S.%f')
        amz_date = t.strftime('%Y%m%dT%H%M%SZ')
        date_stamp = t.strftime('%Y%m%d')

        headers = {
            'host': self.host,
            'x-amz-date': amz_date,
            'x-amz-security-token': ''
        }

        # Add session token if available
        if self.signer.session_token:
            headers['x-amz-security-token'] = self.signer.session_token

        canonical_request = self.signer.create_canonical_request(method, uri, "", headers, payload)
        headers["Authorization"] = self.signer.get_authorization_header(amz_date, date_stamp, canonical_request)
        # Host and amazing security token are not part of the singing
        headers.pop("host", None)
        if not self.signer.session_token:
            headers.pop("x-amz-security-token", None)
        # Inject the additional headers if passed outside of the authorization signing process
        if headers_additional:
            headers.update(headers_additional)
        return headers

    @staticmethod
    def base64_encode_for_lambda(event: dict | str):
        if isinstance(event, dict):
            event = json.dumps(event)
        return base64.b64encode(event.encode('utf-8')).decode('utf-8')

    def lambda_list_functions(self):
        method = "GET"
        uri = "/2015-03-31/functions/"
        headers = self._get_headers(method=method, uri=uri)
        input = {
            "method": method,
            "uri": uri,
            "headers": headers,
            "url": f"{self.endpoint}/functions/"
        }
        response = requests.get(input["url"], headers=input["headers"])
        return response.status_code, response.json()

    def lambda_invoke(self, function_name, payload):
        method = "POST"
        uri = f"/2015-03-31/functions/{function_name}/invocations"
        payload_json = json.dumps(payload)
        headers = self._get_headers(method=method, uri=uri, payload=payload_json)
        input = {
            "method": method,
            "uri": uri,
            "headers": headers,
            "url": f"{self.endpoint}/functions/{function_name}/invocations",
            "payload": payload_json,
        }
        response = requests.post(input["url"], headers=input["headers"], data=input["payload"])
        return response.status_code, response.json()

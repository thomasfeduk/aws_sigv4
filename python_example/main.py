import aws_sigv4

# Set your config here
# Normally would be loaded using an .env file security, but as this is only a demo a hard-coded dict will do
aws_config = {
    "access_key": "",
    "secret_key": "",
    "session_token": "",
    "region": "us-east-1",
    "function_name": "your_function_name",
}


# The raw payload to pass to the lambda
payload = {"color": "red", "price": "100", "sku": "12345"}

# Init the simple client
lambda_client = aws_sigv4.AWSClient(aws_config, "lambda")

# Execute either list functions or the lambda itself:
# print(lambda_client.lambda_list_functions())
print(lambda_client.lambda_invoke(aws_config["function_name"], payload=payload))

# AWS Sigv4 Generation 
### via Python, Javascript and in Postman pre-request scripts

## Purpose

Connecting to AWS APIs for troubleshooting, debugging and testing purposes is standard practice for cloud engineers. For most common languages, AWS provides full SDKs (i.e. [boto3](https://github.com/boto/boto3)) to facilitate not only the communication with their various service layer APIs.

The ASK also handles the complex authentication methodology as specified by the [AWS Sigv4](https://docs.aws.amazon.com/AmazonS3/latest/API/sig-v4-authenticating-requests.html) process. This includes various HMAC hashing operations, generation and structureing of canonical requests, and undergoing the lengthy key-derivation process for the authentication headers and singing requirements.

In this repository, I have written a simple, straight forward and easy-to-follow implementation of the entire AWS Sigv4 generation and handling process for:
- [**Python**](python_example/aws_sigv4.py)
- [**Javascript**](javascript_example/pre-request_script.js) (pre-request script compatible)
- A ready-to-go Postman [**collection**](postman_collection.json) and [**environment**](postman_environment.json) file with a pre-configured example

### Why not just use the official SDK?

I have found in more than one occurrence, the AWS SDK was either:
- Not available for the language or environment needed
- Too large for a given situation (boto3 v1.26.104 consists of 1,777 files and 1,668,943 lines of code)
- Or is inadequate if you have a need to examine the raw literal API payload requests and response handling at the API/HTTP level for troubleshooting possible AWS-side infrastructure bugs
  - For example: I discovered a bug in the AWS Codestar SDK in 2022 that would call the Codestar APis differently on Mac vs PC/Linux which caused the Codestar project initialization to fail in an unrecoverable state that rendered the console incapable of interacting with it.

### But Postman supports AWS Sigv4 under the 'Authentication' tab right??
True, Postman does support AWS Sigv4 for proper Requests, however it is ***not availiable*** for use in **pre-request** scripts if you want to publish a Kinesis message, invoke a Lambda or call any other AWS service before the primary request executes. Additionally, you cannot load the Javascript SDK via NPM as pre-request scripts can't load NPM modules.
- For example, I have a number of Postman requests or runners I need to execute that fetch a fresh record from an API which populated into a DynamoDB as the result of a Kinesis-Lambda trigger. Until now, I had to use a separate tool in addition to Postman to perform these tests and switch back-and-fourth.

By using AWS Sigv4 in pre-request scripts, an engineer can now perform full end-to-end testing of not only their APIs, but now also their Lambdas, verify behavior of their Kinesis consumers and perform any other infrastructure related test, trigger or resulting state verification that is needed directly from within Postman without switching between tools.

#### One click of the **Send** button in Postman can now:
1. Read the `userId` from your Postman environment variable
1. Publish an order event type to a Kinesis stream for that user id
1. Call an internal-facing Lambda that reads the latest order for that user, which the pre-request script parses out an order ID from the response and stores in a new Postman environment variable `orderId`
1. Write an order metadata file to S3 containing info about the newly created `orderId` 
1. Then execute the primary API call to `/orders/{orderId}` with the newly created order ID read from the just-set `orderId` variable 

## Instructions _**(Postman Collection)**_
The provided collection includes a working example of a Lambda invocation and display of its output. 

**Instructions:**
1. Import the [**collection**](postman_collection.json) and [**environment**](postman_environment.json) file
1. Ensure the following env variables are set:
    * `AWS-AccessKeyId`
    * `AWS-SecretAccessKey`
    * `AWS-SessionToken` (If applicable, leave blank otherwise)
    * `AWS-Region`
    * `FunctionName`
    * `FunctionPayload`
1. Click `Send`
1. Open the Postman `Console` (bottom left) to see the function output.

# Invoke AWS Lambda with SigV4 in Rust

Example project showing how to invoke a Lambda function using the AWS Lambda API. You can read more about the API here: https://docs.aws.amazon.com/lambda/latest/dg/API_Invoke.html

I leveraged [David Barsky's project](https://github.com/davidbarsky/sigv4) which can be found in the AWS SDK for Rust [project](https://crates.io/crates/aws-sigv4) to help me sign the request.

# Setup

To run the project, you'll need to modify `run.rs` file in `src/bin/`. You need to add your URL, AWS access key, AWS secret key, and region.

For the URL, you'll need to replace the region and function name in the example below.

```https://lambda.[AWS region].amazonaws.com/2015-03-31/functions/[AWS Lambda function name]/invocations```

From the command line, you can run the project with the following command.

```cargo run --bin run```

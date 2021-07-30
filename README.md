### AWS S3 Cloudfront Okta

Terraform module for standing up a static website on aws with okta authentication. Heavily inspired by [this](https://github.com/aws-samples/lambdaedge-openidconnect-samples) aws example repo. Translated to Python and Terraform. 

### Requirements
- Terraform ([install instructions](https://learn.hashicorp.com/tutorials/terraform/install-cli)) 
- An existing Route 53 Hosted Zone
- awscli 
- python3

### Resources Created
- ACM Certificate for Specified Domain
- Route53 Entry for ACM certification
- Route53 Entry for Specified domain pointed to cloudfront
- Cloudfront Distribution that points to S3
- Lambda@Edge function to carry out openid with okta
- Secrets Manager secret with okta info
- S3 Bucket that holds site files

### Note
Even after terraform apply your bucket and secret will be empty. 
To upload to your bucket use either `aws s3 sync` or `aws s3 cp` from the awscli. 
To upload your secret use `upload_okta_config.py` in the `/bin` directory. 

The layout of the okta_config json is shown below for reference. 

```json
okta_settings = {
    "AUTH_REQUEST": {
        "client_id": <okta_client_id>,
        "response_type": "code",
        "scope": "openid email groups",
        "redirect_uri": "https://<website_domain_name>/_callback",
    },
    "TOKEN_REQUEST": {
        "client_id": <okta_client_id>,
        "redirect_uri": "https://<website_domain_name>/_callback",
        "grant_type": "authorization_code",
        "client_secret": okta_secret,
    },
    "JWT_KEY": <jwt_key>,
    "DISCOVERY_DOCUMENT": "https://<okta_domain_name>/.well-known/openid-configuration",
    "SESSION_DURATION": 300,
    "BASE_URL": "https://<okta_domain_name>/",
    "CALLBACK_PATH": "/_callback",
    "DOMAIN_NAME": "https://<website_domain_name>",
}
```
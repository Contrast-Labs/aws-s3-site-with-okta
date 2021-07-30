provider "aws" {
  region = "us-east-1"
  default_tags {
    tags = {
      Terraform = "true"
    }
  }
}

module "okta-s3-site" {
  source      = "git@github.com:Contrast-Labs/aws-s3-site-with-okta.git"
  domain_name = "example.com"
  hosted_zone = "example.com"
}

output "secret_name" {
  value = module.okta-s3-site.secret_name
}

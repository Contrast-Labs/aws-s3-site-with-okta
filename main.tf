// Route 53 setup 
data "aws_route53_zone" "website" {
  name         = var.hosted_zone
  private_zone = false
}

resource "aws_route53_record" "website" {
  depends_on = [
    aws_cloudfront_distribution.website
  ]

  zone_id = data.aws_route53_zone.website.zone_id
  name    = var.domain_name
  type    = "A"

  alias {
    name                   = aws_cloudfront_distribution.website.domain_name
    zone_id                = "Z2FDTNDATAQYW2" // Constant for all cloudfront domains
    evaluate_target_health = false
  }
}

resource "aws_acm_certificate" "website" {
  domain_name       = var.domain_name
  validation_method = "DNS"
}

resource "aws_route53_record" "acm_validation_records" {
  for_each = {
    for dvo in aws_acm_certificate.website.domain_validation_options : dvo.domain_name => {
      name   = dvo.resource_record_name
      record = dvo.resource_record_value
      type   = dvo.resource_record_type
    }
  }

  allow_overwrite = true
  name            = each.value.name
  records         = [each.value.record]
  ttl             = 60
  type            = each.value.type
  zone_id         = data.aws_route53_zone.website.zone_id

}

resource "aws_acm_certificate_validation" "website" {
  certificate_arn         = aws_acm_certificate.website.arn
  validation_record_fqdns = [for record in aws_route53_record.acm_validation_records : record.fqdn]
}


// S3 Setup 
resource "aws_s3_bucket" "website" {
  bucket = var.domain_name
  acl    = "private"
}

resource "aws_s3_bucket_public_access_block" "website" {
  bucket = aws_s3_bucket.website.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_policy" "website" {
  bucket = aws_s3_bucket.website.id
  depends_on = [
    aws_s3_bucket_public_access_block.website // Helps with deletion order problems
  ]
  policy = jsonencode({
    Version = "2012-10-17"
    Id      = "MYBUCKETPOLICY"
    Statement = [
      {
        Sid    = "1"
        Action = "s3:GetObject"
        Effect = "Allow"
        Resource = [
          "${aws_s3_bucket.website.arn}/*"
        ]
        Principal = {
          AWS = aws_cloudfront_origin_access_identity.website.iam_arn
        }
      }
    ]
  })
}


// Cloudfront setup 
resource "aws_cloudfront_distribution" "website" {
  depends_on = [
    aws_s3_bucket.website
  ]

  origin {
    domain_name = aws_s3_bucket.website.bucket_domain_name
    origin_id   = "s3-cloudfront"

    s3_origin_config {
      origin_access_identity = aws_cloudfront_origin_access_identity.website.cloudfront_access_identity_path
    }
  }

  enabled             = true
  is_ipv6_enabled     = true
  default_root_object = "index.html"

  aliases = [var.domain_name]

  default_cache_behavior {
    allowed_methods = [
      "GET",
      "HEAD",
    ]

    cached_methods = [
      "GET",
      "HEAD",
    ]

    target_origin_id = "s3-cloudfront"

    forwarded_values {
      query_string = true

      cookies {
        forward = "all"
      }
    }

    lambda_function_association {
      event_type = "viewer-request"
      lambda_arn = aws_lambda_function.auth_lambda.qualified_arn
    }

    viewer_protocol_policy = "redirect-to-https"
    min_ttl                = 0
    default_ttl            = 86400
    max_ttl                = 31536000
  }

  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }

  viewer_certificate {
    acm_certificate_arn      = aws_acm_certificate.website.arn
    ssl_support_method       = "sni-only"
    minimum_protocol_version = "TLSv1.2_2019"
  }

  wait_for_deployment = false
}

resource "aws_cloudfront_origin_access_identity" "website" {
  comment = "access-identity-${aws_s3_bucket.website.bucket_domain_name}"
}

// Lambda Setup 
resource "null_resource" "pip_install" {
  provisioner "local-exec" {
    command     = "pip3 install -t . -r requirements.txt"
    working_dir = "${path.module}/lambdas/auth"
  }
}

resource "local_file" "okta_secret_name" {
  content  = aws_secretsmanager_secret.okta_settings.name
  filename = "${path.module}/lambdas/auth/okta-key.txt"
}

data "archive_file" "auth_lambda" {
  depends_on = [
    null_resource.pip_install,
    local_file.okta_secret_name
  ]
  type        = "zip"
  source_dir  = "${path.module}/lambdas/auth"
  output_path = "/tmp/auth.zip"
}

resource "aws_lambda_function" "auth_lambda" {
  depends_on = [
    data.archive_file.auth_lambda
  ]
  function_name    = "${replace(var.domain_name, ".", "-")}-auth-lambda"
  role             = aws_iam_role.auth_lambda.arn
  handler          = "auth.lambda_handler"
  runtime          = "python3.7"
  timeout          = 5
  publish          = true
  filename         = data.archive_file.auth_lambda.output_path
  source_code_hash = data.archive_file.auth_lambda.output_base64sha256
}

resource "aws_iam_policy" "get_okta_settings" {
  name = "${var.domain_name}-get-okta-settings"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [
          "secretsmanager:GetSecretValue",
        ]
        Effect   = "Allow"
        Resource = aws_secretsmanager_secret.okta_settings.arn
      },
    ]
  })
}

resource "aws_iam_role" "auth_lambda" {
  name = "${var.domain_name}-auth-lambda"

  // TODO: replace basic Execution Role
  managed_policy_arns = [
    "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole",
    aws_iam_policy.get_okta_settings.arn
  ]

  assume_role_policy = jsonencode(
    {
      Statement = [
        {
          Action = "sts:AssumeRole"
          Effect = "Allow"
          Principal = {
            Service = ["lambda.amazonaws.com", "edgelambda.amazonaws.com"]
          }
        }
      ]
      Version = "2012-10-17"
    }
  )
}

// Secret
resource "aws_secretsmanager_secret" "okta_settings" {
  name = "okta_settings/${var.domain_name}"
}

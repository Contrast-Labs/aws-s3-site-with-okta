output "s3_bucket_id" {
  value = aws_s3_bucket.website.id
}

output "secret_name" {
  value = aws_secretsmanager_secret.okta_settings.name
}

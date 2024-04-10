resource "aws_cloudtrail" "cloudtrail" {
  name                       = "cloudtrail-example"
  s3_bucket_name             = aws_s3_bucket.cloudtrail_s3.id
  kms_key_id                 = aws_kms_key.cloudtrail_kms_key.arn
  enable_log_file_validation = true
  is_multi_region_trail      = true
  enable_logging             = true

  depends_on = [
    aws_s3_bucket.cloudtrail_s3,
    data.aws_iam_policy_document.cloudtrail_s3_policy,
    aws_kms_key.cloudtrail_kms_key
  ]
}

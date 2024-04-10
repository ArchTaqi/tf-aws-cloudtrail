resource "aws_s3_bucket" "cloudtrail_s3" {
  bucket        = "cloudtrail-bucket"
  force_destroy = true
}

resource "aws_s3_bucket_acl" "s3_bucket" {
  bucket = aws_s3_bucket.cloudtrail_s3.id

  acl = "private"
}

resource "aws_s3_bucket_public_access_block" "pub_access" {
  bucket                  = aws_s3_bucket.cloudtrail_s3.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}


resource "aws_s3_bucket_policy" "cloudtrail_s3_policy" {
  bucket = aws_s3_bucket.cloudtrail_s3.id
  policy = data.aws_iam_policy_document.cloudtrail_s3_policy.json
}

data "aws_iam_policy_document" "cloudtrail_s3_policy" {
  statement {
    sid       = "AWSCloudTrailAclCheck"
    effect    = "Allow"
    resources = ["${aws_s3_bucket.cloudtrail_s3.arn}"]
    actions   = ["s3:GetBucketAcl"]

    condition {
      test     = "StringEquals"
      variable = "AWS:SourceArn"
      values   = ["arn:aws:cloudtrail:eu-west-1:${data.aws_caller_identity.current.account_id}:trail/cloudtrail-${terraform.workspace}"]
    }

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
  }

  statement {
    sid       = "AWSCloudTrailWrite"
    effect    = "Allow"
    resources = ["${aws_s3_bucket.cloudtrail_s3.arn}/AWSLogs/${data.aws_caller_identity.current.account_id}/*"]
    actions   = ["s3:PutObject"]

    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }

    condition {
      test     = "StringEquals"
      variable = "AWS:SourceArn"
      values   = ["arn:aws:cloudtrail:eu-west-1:${data.aws_caller_identity.current.account_id}:trail/cloudtrail-${terraform.workspace}"]
    }

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
  }
}

############################################################
# c6  Ransomware target: no versioning, no object lock, SSE-C allowed, surprise expiration
############################################################
resource "aws_s3_bucket" "ransom_target" {
  bucket        = "roqy-lab-customer-uploads-${local.sfx}"
  force_destroy = true
  tags          = { "roqy-plant" = "s3-no-versioning-objectlock s3-sse-c-allowed s3-lifecycle-expiration" }
}

# Versioning is simply never enabled (no aws_s3_bucket_versioning) and object lock is off.

resource "aws_s3_bucket_lifecycle_configuration" "surprise_expiry" {
  bucket = aws_s3_bucket.ransom_target.id
  rule {
    id     = "cleanup-tmp"
    status = "Enabled"
    filter {} # whole bucket, despite the friendly name
    expiration {
      days = 1
    }
  }
}

# Since April 2026 new buckets block SSE-C by default. Re-allow it explicitly (Codefinger 2025 vector).
# The provider schema may not expose BlockedEncryptionTypes yet, so use the CLI.
resource "terraform_data" "allow_sse_c" {
  triggers_replace = [aws_s3_bucket.ransom_target.id]
  provisioner "local-exec" {
    command = "aws s3api put-bucket-encryption --bucket ${aws_s3_bucket.ransom_target.id} --region ${var.region} --profile ${var.aws_profile} --server-side-encryption-configuration '{\"Rules\":[{\"ApplyServerSideEncryptionByDefault\":{\"SSEAlgorithm\":\"AES256\"},\"BlockedEncryptionTypes\":{\"EncryptionType\":[\"NONE\"]}}]}'"
  }
}

resource "aws_s3_object" "ransom_sample" {
  bucket  = aws_s3_bucket.ransom_target.id
  key     = "invoices/2026/sample-invoice.txt"
  content = "roqy-lab dummy object. No real data."
}

############################################################
# c4  AI-named bucket (W41) + cross-account grant / truly public policy (allow_public)
############################################################
resource "aws_s3_bucket" "llm_rag" {
  bucket        = "roqy-lab-llm-rag-data-${local.sfx}"
  force_destroy = true
  tags          = { "roqy-plant" = "s3-ai-named-bucket s3-cross-account-grant s3-public-read-policy s3-public-write" }
}

resource "aws_s3_object" "rag_sample" {
  bucket  = aws_s3_bucket.llm_rag.id
  key     = "embeddings/README.txt"
  content = "roqy-lab dummy object. No real data."
}

# Bucket-level BPA: kept ON unless allow_public. Account-level BPA is never touched.
resource "aws_s3_bucket_public_access_block" "llm_rag" {
  bucket                  = aws_s3_bucket.llm_rag.id
  block_public_acls       = true
  ignore_public_acls      = true
  block_public_policy     = !var.allow_public
  restrict_public_buckets = !var.allow_public
}

locals {
  rag_statements = concat(
    local.has_foreign ? [{
      Sid       = "PartnerAccountReadWrite"
      Effect    = "Allow"
      Principal = { AWS = "arn:aws:iam::${var.foreign_account_id}:root" }
      Action    = ["s3:GetObject", "s3:PutObject", "s3:ListBucket"]
      Resource  = [aws_s3_bucket.llm_rag.arn, "${aws_s3_bucket.llm_rag.arn}/*"]
    }] : [],
    var.allow_public ? [{
      Sid       = "PublicReadWritePLANT"
      Effect    = "Allow"
      Principal = "*"
      Action    = ["s3:GetObject", "s3:PutObject"]
      Resource  = "${aws_s3_bucket.llm_rag.arn}/*"
    }] : []
  )
}

resource "aws_s3_bucket_policy" "llm_rag" {
  count      = length(local.rag_statements) > 0 ? 1 : 0
  bucket     = aws_s3_bucket.llm_rag.id
  policy     = jsonencode({ Version = "2012-10-17", Statement = local.rag_statements })
  depends_on = [aws_s3_bucket_public_access_block.llm_rag]
}

# Absence plants (not created on purpose): AWS Backup vault with Vault Lock, S3 Object Lock.

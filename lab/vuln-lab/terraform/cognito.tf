############################################################
# c16  Cognito: self sign-up, client-writable email, unauth identities with s3:*
############################################################
resource "aws_cognito_user_pool" "open" {
  name = "roqy-lab-customers"

  admin_create_user_config {
    allow_admin_create_user_only = false # anyone can sign up
  }

  # email is mutable and NOT required to be verified before use as identity
  schema {
    name                = "email"
    attribute_data_type = "String"
    mutable             = true
    required            = false
    string_attribute_constraints {
      min_length = 0
      max_length = 2048
    }
  }

  schema {
    name                = "role"
    attribute_data_type = "String"
    mutable             = true
    required            = false
    string_attribute_constraints {
      min_length = 0
      max_length = 64
    }
  }

  tags = { "roqy-plant" = "cognito-self-signup cognito-email-writable" }
}

resource "aws_cognito_user_pool_client" "spa" {
  name            = "roqy-lab-spa"
  user_pool_id    = aws_cognito_user_pool.open.id
  generate_secret = false
  # client can write email AND the custom role attribute (privilege via self-edited claim)
  write_attributes = ["email", "custom:role"]
  read_attributes  = ["email", "custom:role"]
  explicit_auth_flows = [
    "ALLOW_USER_PASSWORD_AUTH",
    "ALLOW_REFRESH_TOKEN_AUTH",
  ]
}

resource "aws_cognito_identity_pool" "unauth" {
  identity_pool_name               = "roqy_lab_guest_pool"
  allow_unauthenticated_identities = true
  allow_classic_flow               = true
  cognito_identity_providers {
    client_id     = aws_cognito_user_pool_client.spa.id
    provider_name = aws_cognito_user_pool.open.endpoint
  }
  tags = { "roqy-plant" = "cognito-unauth-identity-s3" }
}

resource "aws_iam_role" "cognito_unauth" {
  name                 = "roqy-lab-cognito-guest"
  description          = "PLANT cognito-unauth-identity-s3. Guarded by deny-all boundary."
  permissions_boundary = local.boundary_arn
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Federated = "cognito-identity.amazonaws.com" }
      Action    = "sts:AssumeRoleWithWebIdentity"
      Condition = {
        StringEquals             = { "cognito-identity.amazonaws.com:aud" = aws_cognito_identity_pool.unauth.id }
        "ForAnyValue:StringLike" = { "cognito-identity.amazonaws.com:amr" = "unauthenticated" }
      }
    }]
  })
  tags = { "roqy-plant" = "cognito-unauth-identity-s3" }
}

resource "aws_iam_role_policy" "cognito_unauth_s3" {
  name = "guest-s3"
  role = aws_iam_role.cognito_unauth.id
  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = "s3:*", Resource = "*" }]
  })
}

resource "aws_cognito_identity_pool_roles_attachment" "unauth" {
  identity_pool_id = aws_cognito_identity_pool.unauth.id
  roles = {
    unauthenticated = aws_iam_role.cognito_unauth.arn
  }
}

data "archive_file" "lambda" {
  type        = "zip"
  source_file = "${path.module}/lambda_src/handler.py"
  output_path = "${path.module}/.build/lambda.zip"
}

resource "aws_iam_role" "lambda_exec" {
  name = "roqy-lab-lambda-exec"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
  tags = { "roqy-plant" = "infra" }
}

resource "aws_iam_role_policy_attachment" "lambda_logs" {
  role       = aws_iam_role.lambda_exec.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

############################################################
# c14  Lambda with secret-looking env vars (FAKE), Principal * policy, optional public URL
############################################################
resource "aws_lambda_function" "public_fn" {
  function_name    = "roqy-lab-payments-webhook"
  role             = aws_iam_role.lambda_exec.arn
  runtime          = "python3.12"
  handler          = "handler.handler"
  filename         = data.archive_file.lambda.output_path
  source_code_hash = data.archive_file.lambda.output_base64sha256
  timeout          = 3
  memory_size      = 128

  environment {
    variables = {
      STRIPE_SECRET_KEY     = local.fake.stripe
      LEGACY_AWS_ACCESS_KEY = local.fake.aws_key_id
      LEGACY_AWS_SECRET_KEY = local.fake.aws_secret
      DB_PASSWORD           = local.fake.db_pass
      ROQY_LAB_NOTE         = "ALL VALUES HERE ARE FAKE"
    }
  }
  tags = { "roqy-plant" = "lambda-secret-env lambda-policy-principal-star lambda-url-auth-none" }
}

resource "aws_cloudwatch_log_group" "lambda" {
  name = "/aws/lambda/${aws_lambda_function.public_fn.function_name}"
  # retention_in_days intentionally unset -> never expire (PLANT log-group-no-retention)
  tags = { "roqy-plant" = "log-group-no-retention" }
}

# Resource policy with Principal "*" (any AWS account can invoke). Function is harmless.
resource "aws_lambda_permission" "any_principal" {
  statement_id  = "RoqyLabAnyPrincipalInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.public_fn.function_name
  principal     = "*"
}

resource "aws_lambda_function_url" "public" {
  count              = var.allow_public ? 1 : 0
  function_name      = aws_lambda_function.public_fn.function_name
  authorization_type = "NONE"
}

resource "aws_lambda_permission" "url_public" {
  count                  = var.allow_public ? 1 : 0
  statement_id           = "FunctionURLAllowPublicAccess"
  action                 = "lambda:InvokeFunctionUrl"
  function_name          = aws_lambda_function.public_fn.function_name
  principal              = "*"
  function_url_auth_type = "NONE"
}

############################################################
# c14  API Gateway HTTP API route with NO authorizer -> Lambda (throttled hard)
############################################################
resource "aws_apigatewayv2_api" "http" {
  name          = "roqy-lab-public-api"
  protocol_type = "HTTP"
  tags          = { "roqy-plant" = "apigw-route-no-auth" }
}

resource "aws_apigatewayv2_integration" "lambda" {
  api_id                 = aws_apigatewayv2_api.http.id
  integration_type       = "AWS_PROXY"
  integration_uri        = aws_lambda_function.public_fn.invoke_arn
  payload_format_version = "2.0"
}

resource "aws_apigatewayv2_route" "no_auth" {
  api_id             = aws_apigatewayv2_api.http.id
  route_key          = "POST /admin/refund"
  authorization_type = "NONE"
  target             = "integrations/${aws_apigatewayv2_integration.lambda.id}"
}

resource "aws_apigatewayv2_stage" "default" {
  api_id      = aws_apigatewayv2_api.http.id
  name        = "$default"
  auto_deploy = true
  default_route_settings {
    throttling_burst_limit = 2
    throttling_rate_limit  = 1
  }
  tags = { "roqy-plant" = "apigw-route-no-auth" }
}

resource "aws_lambda_permission" "apigw" {
  statement_id  = "AllowApiGatewayInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.public_fn.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_apigatewayv2_api.http.execution_arn}/*/*"
}

############################################################
# c14  ECS task definition with plaintext secret env (no cluster/service needed, free)
############################################################
resource "aws_ecs_task_definition" "secret_env" {
  family                   = "roqy-lab-billing-worker"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = "256"
  memory                   = "512"
  container_definitions = jsonencode([{
    name         = "worker"
    image        = "public.ecr.aws/docker/library/busybox:latest"
    essential    = true
    command      = ["sleep", "3600"]
    portMappings = [{ containerPort = 6379, protocol = "tcp" }]
    environment = [
      { name = "DB_PASSWORD", value = local.fake.db_pass },
      { name = "GITHUB_TOKEN", value = local.fake.gh_token },
      { name = "AWS_SECRET_ACCESS_KEY", value = local.fake.aws_secret }
    ]
  }])
  tags = { "roqy-plant" = "ecs-taskdef-secret-env" }
}

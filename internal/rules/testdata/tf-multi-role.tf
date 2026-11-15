resource "aws_iam_role" "safe" {
  name = "safe"
  assume_role_policy = <<POLICY
{"Statement":{"Effect":"Allow","Action":"sts:AssumeRoleWithWebIdentity","Principal":{"Federated":"arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"},"Condition":{"StringEquals":{"token.actions.githubusercontent.com:sub":"repo:example-org/example-repo:ref:refs/heads/main"}}}}
POLICY
}

resource "aws_iam_role" "second" {
  name = "second"
  assume_role_policy = <<POLICY
{"Statement":{"Effect":"Allow","Action":"sts:AssumeRole","Principal":"*"}}
POLICY
}

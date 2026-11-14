resource "aws_iam_role" "broken" {
  name = "broken"
  assume_role_policy = <<POLICY
{"Statement":{"Effect":"Allow","Action":"sts:AssumeRole","Principal":"*"}}
}

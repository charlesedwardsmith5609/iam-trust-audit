resource "aws_iam_role" "badjson" {
  name = "badjson"
  assume_role_policy = <<POLICY
{"Statement": [oops
POLICY
}

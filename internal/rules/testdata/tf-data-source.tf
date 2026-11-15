resource "aws_iam_role" "viadata" {
  name               = "viadata"
  assume_role_policy = data.aws_iam_policy_document.trust.json
}

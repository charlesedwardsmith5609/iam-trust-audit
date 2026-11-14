resource "aws_iam_role" "indented" {
  name = "indented"
  assume_role_policy = <<-EOT
    {
      "Statement": {
        "Effect": "Allow",
        "Action": "sts:AssumeRole",
        "Principal": "*"
      }
    }
    EOT
}

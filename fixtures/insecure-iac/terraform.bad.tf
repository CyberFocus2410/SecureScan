resource "aws_s3_bucket" "insecure_bucket" {
  bucket = "my-insecure-public-bucket"
  acl    = "public-read"
}

resource "aws_security_group" "open_ssh" {
  name = "allow_all_ssh"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_iam_policy" "wildcard_policy" {
  name = "wildcard_admin"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action   = "*"
        Effect   = "Allow"
        Resource = "*"
      }
    ]
  })
}

provider "aws" {
  region     = var.aws_region
  access_key = var.aws_access_key_id
  secret_key = var.aws_secret_access_key

  default_tags {
    tags = {
      environment = var.env_prefix
      terraform   = "true"
    }
  }
}
######## CREATE ROLES ########

# define and get info on needed policies for both roles


# A "data" block in Terraform is used to READ/LOOK UP existing resources
# instead of creating new ones. Here we are looking up an existing IAM policy.
data "aws_iam_policy" "AmazonSSMManagedInstanceCore" {

  # "aws_iam_policy" → The TYPE of data source we are querying.
  # This tells Terraform: "Go fetch information about an IAM policy in AWS".

  # "AmazonSSMManagedInstanceCore" → The NAME/IDENTIFIER we give inside Terraform.
  # This is how we'll reference this data later, like:
  # data.aws_iam_policy.AmazonSSMManagedInstanceCore.arn

  # The ARN (Amazon Resource Name) of the existing policy we want to fetch.
  # In this case, it's an AWS-managed policy that allows EC2 instances
  # to use Systems Manager (SSM) for remote management without SSH.
  arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

data "aws_iam_policy" "AmazonEC2ContainerRegistryFullAccess" {
  arn = "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryFullAccess"
}

data "aws_iam_policy" "AmazonSSMFullAccess" {
  arn = "arn:aws:iam::aws:policy/AmazonSSMFullAccess"
}


# create role for ec2 service for app-server

resource "aws_iam_role" "app-server-role" { #"app-server-role" is Local Terraform name (how we reference it inside our code).
  name = "app-server-role"                  #This is the actual name of the IAM role in AWS.

  #<<EOF → Marks the start of a multi-line string and EOF → Marks the end of that string.
  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "sts:AssumeRole",
      "Principal": {
        "Service": "ec2.amazonaws.com"
      },
      "Effect": "Allow",
      "Sid": ""
    }
  ]
}
EOF
}

# attach the needed policies to the created ec2 role
resource "aws_iam_role_policy_attachment" "policy-attach-ssm" {
  role       = aws_iam_role.app-server-role.name
  policy_arn = data.aws_iam_policy.AmazonSSMManagedInstanceCore.arn
}

resource "aws_iam_role_policy_attachment" "policy-attach-ecr-full" {
  role       = aws_iam_role.app-server-role.name
  policy_arn = data.aws_iam_policy.AmazonEC2ContainerRegistryFullAccess.arn
}

# define instance profile, so we can assign the role to our ec2 instance
resource "aws_iam_instance_profile" "app-server-role" {
  name = "app-server-role"
  role = aws_iam_role.app-server-role.name
}


# create role for ec2 service for gitlab-runner-server
resource "aws_iam_role" "gitlab-runner-role" {
  name = "gitlab-runner-role"

  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "sts:AssumeRole",
      "Principal": {
        "Service": "ec2.amazonaws.com"
      },
      "Effect": "Allow",
      "Sid": ""
    }
  ]
}
EOF
}

resource "aws_iam_role_policy_attachment" "policy-attach-ssm-gitlab" {
  role       = aws_iam_role.gitlab-runner-role.name
  policy_arn = data.aws_iam_policy.AmazonSSMFullAccess.arn
}

resource "aws_iam_role_policy_attachment" "policy-attach-ecr-full-gitlab" {
  role       = aws_iam_role.gitlab-runner-role.name
  policy_arn = data.aws_iam_policy.AmazonEC2ContainerRegistryFullAccess.arn
}

resource "aws_iam_instance_profile" "gitlab-runner-role" {
  name = "gitlab-runner-role"
  role = aws_iam_role.gitlab-runner-role.name
}

######## CREATE NETWORKING RESOURCES ########

# fetch available zones for the configured region 
data "aws_availability_zones" "available" {}

# create "main" vpc to launch our instances in
module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "5.1.0"

  name = "main"

  cidr            = "10.0.0.0/16"
  private_subnets = ["10.0.1.0/24", "10.0.2.0/24", "10.0.3.0/24"]
  public_subnets  = ["10.0.101.0/24", "10.0.102.0/24", "10.0.103.0/24"]

  azs = data.aws_availability_zones.available.names

  enable_nat_gateway = true
  enable_vpn_gateway = true

  tags = {
    terraform   = "true"
    environment = var.env_prefix
  }
}

resource "aws_security_group" "main" {
  name   = "main"
  vpc_id = data.aws_vpc.main.id

  ingress {
    description = "Allow inbound from all 10.0.0.0/16"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["10.0.0.0/16"]
  }

  egress {
    description = "Allow all outbound"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "main"
  }
}


resource "aws_security_group" "app-server" {
  name   = "app-server"
  vpc_id = data.aws_vpc.main.id

  ingress {
    description = "Allow inbound from all 10.0.0.0/16"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["10.0.0.0/16"]
  }
  ingress {
    description = "Allow inbound from  0.0.0.0/0 port 3000"
    from_port   = 3000
    to_port     = 3000
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  egress {
    description = "Allow all outbound"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags = {
    Name = "app-server"
  }

}

######## CREATE EC2 SERVERS ########

module "ec2_app_server" {
  depends_on = [aws_security_group.app-server] #Forces Terraform to create the security group first before creating this EC2.

  # TF module that creates EC2 instances: https://registry.terraform.io/modules/terraform-aws-modules/ec2-instance/aws/1.0.4             
  source  = "terraform-aws-modules/ec2-instance/aws"
  version = "5.2.1"

  name = "app-server"

  instance_type               = "t3.small"
  availability_zone           = element(data.aws_availability_zones.available.names, 0) # get first az from available zones
  ami                         = data.aws_ami.ubuntu.id
  iam_instance_profile        = data.aws_iam_instance_profile.app-server-role.name
  associate_public_ip_address = true
  vpc_security_group_ids      = [aws_security_group.app-server.id]
  subnet_id                   = module.vpc.public_subnets[0]
  user_data                   = base64encode(local.script)
  #user_data is a script that runs automatically when the EC2 instance boots for the first time.
  #It’s usually a shell script (for Linux) or a PowerShell script (for Windows).
  #AWS passes it to the instance’s cloud-init service (on Ubuntu/Amazon Linux/other cloud-init enabled OS).

  tags = {
    Terraform   = "true"
    Environment = var.env_prefix
    Name        = "app-server"
  }

  root_block_device = [{
    volume_type           = "gp3"
    volume_size           = 16
    delete_on_termination = true
  }]
}

module "ec2_gitlab_runner" {
  depends_on = [aws_security_group.main]
  source     = "terraform-aws-modules/ec2-instance/aws"
  version    = "5.2.1"

  name = "gitlab-runner"

  instance_type               = "t3.small"
  availability_zone           = element(data.aws_availability_zones.available.names, 0)
  ami                         = data.aws_ami.ubuntu.id
  iam_instance_profile        = data.aws_iam_instance_profile.gitlab-runner-role.name
  associate_public_ip_address = true
  vpc_security_group_ids      = [aws_security_group.main.id]
  subnet_id                   = module.vpc.public_subnets[0]
  user_data                   = base64encode(local.script-gitlab)

  tags = {
    Terraform   = "true"
    Environment = var.env_prefix
    Name        = "gitlab-runner"
  }

  root_block_device = [{
    volume_type           = "gp3"
    volume_size           = 24
    delete_on_termination = true
  }]

}

### The versions used in the project

providers

- hashicorp/aws = 5.3

modules

- terraform-aws-modules/ec2-instance/aws = 5.2.1
- terraform-aws-modules/vpc/aws = 5.1.0

</br>

### Following resources are created with this TF script

- role "app-server-role" with policies:
  - AmazonSSMManagedInstanceCore
  - AmazonEC2ContainerRegistryFullAccess
- role "gitlab-runner-role" with policies:
  - AmazonSSMFullAccess
  - AmazonEC2ContainerRegistryFullAccess
- vpc "main"
- security group "main"
- security group "app-server"
- ec2 server "ec2_app_server" with:
  - Role: app-server-role
  - Security Group: app-server
- ec2 server "ec2_gitlab_runner"
  - Role: gitlab-runner-role
  - Security Group: main

NOTE: both servers are using the Ubuntu image: ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-\*

</br>

### Create _terraform.tfvars_ file and set following variables inside before running the script

- aws_access_key_id
- aws_secret_access_key
- aws_region
- env_prefix
- runner_registration_token

NOTEs:

- _variables.tf_ vs _terraform.tfvars_

_variables.tf_ declares all variables used in script and is normal part of tf script. While _terraform.tfvars_ assigns values to those declared variables including secret variables, so it should be created and used locally, not commited to the repo as part of code.

- Format inside terraform.tfvars:

```console
    my_var_one="value-one"
    my_var_two="value-two"
```

</br>

### Terraform commands to execute the script

```console
# initialise project & download providers
terraform init

# preview what will be created with apply & see if any errors
terraform plan

# exeucute with preview
terraform apply -var-file terraform.tfvars

# execute without preview
terraform apply -var-file terraform.tfvars -auto-approve

# destroy everything
terraform destroy

# show resources and components from current state
terraform state list
```

Notes:

- For verbose output, set `export TF_LOG=DEBUG` before running TF commands
- When using s3 bucket as remote state, you need to set `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_DEFAULT_REGION` env vars in the session, before executing `terraform init` and `terraform plan` commands

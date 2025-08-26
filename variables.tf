variable "aws_access_key_id" {
  default = ""
}
variable "aws_secret_access_key" {
  default = ""
}
variable "aws_region" {
  default = "eu-west-3"
}
variable "env_prefix" {
  default = "dev"
}
variable "runner_registration_token" {
  default = ""
  # will not be displayed in tf output
  sensitive = true
}

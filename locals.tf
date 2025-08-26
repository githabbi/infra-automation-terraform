locals {
  script = templatefile("${path.module}/scripts/script.tpl", {
  })
}

locals {
  script-gitlab = templatefile("${path.module}/scripts/script-gitlab.tpl", {
    # we are passing the registration_token value to the script, for the gitlab-runner register command
    runner_registration_token = var.runner_registration_token
  })
}

output "script" {
  value = local.script
}

output "script-gitlab" {
  value = local.script-gitlab
  # sensitive, cuz registration_token is marked sensitive and script output will not be displayed now
  sensitive = true
}

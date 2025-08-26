#!/bin/bash

# wait 60 seconds until instance fully initialised - needed here so that gitlab-register command is successful
sleep 60

# update package repos
sudo apt update

# Install gitLab runner
curl -L "https://packages.gitlab.com/install/repositories/runner/gitlab-runner/script.deb.sh" | sudo bash
sudo apt install gitlab-runner -y

# Install docker on Ubuntu 22.04
sudo apt  install docker.io -y

# Add gitlab-runner & ubuntu users to docker group
sudo usermod -aG docker gitlab-runner
sudo usermod -aG docker ubuntu

# Start docker to apply the above change
systemctl restart docker

# Install AWS CLI 
sudo apt install awscli -y


## register runner
sudo gitlab-runner register --non-interactive --url "https://gitlab.com/" --token "${runner_registration_token}" --executor "shell"

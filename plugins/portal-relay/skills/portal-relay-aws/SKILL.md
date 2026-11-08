---
name: portal-relay-aws
description: Create an AWS host for a Portal relay - an EC2 instance with a security group and an Elastic IP, or a Lightsail instance with its public ports and a static IP - using the user's existing AWS CLI profile or IAM Identity Center sign-in, and hand the host to portal-relay for deployment. Use when the user wants to run a Portal relay on AWS, EC2, or Lightsail. Do not use for a host that already exists (portal-relay), for Route 53 as the relay's ACME DNS provider (relay configuration), or for other clouds.
license: MIT
---

# Portal relay on AWS

This skill creates and opens the host. `portal-relay` deploys the relay on it. Follow [`../portal-relay/references/provider-contract.md`](../portal-relay/references/provider-contract.md) (the `portal-relay` skill's contract in this same plugin; the path is relative to this file, so it matches the installed version and needs no network) for the phase order, credential rules, and approval rules. This file adds only what is specific to AWS.

## Preflight

- `aws --version`. If the CLI is missing, point to the official AWS CLI install guide and stop.
- `aws sts get-caller-identity --profile <profile>` proves the credentials work in this environment. Report the account and role to the user for confirmation, and do not print or open `~/.aws/credentials` or the SSO cache.

## Authenticate

- With an IAM Identity Center profile that is already configured, the user runs `aws sso login --profile <profile>` on a machine with a browser. Setting the profile up is `aws configure sso`, which needs the organization's start URL and is the user's task.
- Without Identity Center, use the existing profile the user names. Never create long-lived access keys for the user, and never ask for them in chat.
- An SSO session on the user's laptop does not exist in a remote sandbox; check with `get-caller-identity` here.

## Choose EC2 or Lightsail

- **Lightsail**: one fixed monthly bundle with included transfer; simpler for a single relay. Read bundles and prices with `aws lightsail get-bundles` and images with `aws lightsail get-blueprints`.
- **EC2**: more control and instance types; data transfer out is billed per GB, which matters for game-hosting relays. Read prices for the chosen type and region before planning.

Show the estimated monthly cost of the chosen option, including the public IPv4 charge, in the plan.

## EC2

1. Image: the current Ubuntu AMI from the public SSM parameter, for example `aws ssm get-parameter --name /aws/service/canonical/ubuntu/server/24.04/stable/current/arm64/hvm/ebs-gp3/ami-id` (use `amd64` for x86 types; the relay image supports both).
2. `aws ec2 create-security-group --group-name <name> --description "Portal relay" --vpc-id <vpc>`, then `aws ec2 authorize-security-group-ingress --group-id <sg> --ip-permissions file://rules.json` with only the contract's ports. Use a new group; do not edit a shared one.
3. `aws ec2 run-instances --image-id <ami> --instance-type <type> --key-name <key> --security-group-ids <sg> --subnet-id <public subnet> --metadata-options HttpTokens=required --tag-specifications 'ResourceType=instance,Tags=[{Key=Name,Value=<name>}]'`.
4. `aws ec2 allocate-address --domain vpc` and `aws ec2 associate-address --instance-id <id> --allocation-id <alloc>`, so the glue address survives instance replacement.

Rollback: `aws ec2 terminate-instances --instance-ids <id>`, then `aws ec2 release-address --allocation-id <alloc>` and `aws ec2 delete-security-group --group-id <sg>`. An Elastic IP left allocated keeps billing.

## Lightsail

1. `aws lightsail create-instances --instance-names <name> --availability-zone <az> --blueprint-id <ubuntu blueprint> --bundle-id <bundle> --key-pair-name <key>`.
2. `aws lightsail put-instance-public-ports --instance-name <name> --port-infos file://ports.json`. This call **replaces** every open port, so the list must include `22/tcp` as well as the relay ports, or SSH closes. Each entry is `{"fromPort": 443, "toPort": 443, "protocol": "tcp", "cidrs": ["0.0.0.0/0"]}`.
3. `aws lightsail allocate-static-ip --static-ip-name <ip name>` and `aws lightsail attach-static-ip --static-ip-name <ip name> --instance-name <name>`.

Rollback: `aws lightsail delete-instance --instance-name <name>`, then `aws lightsail release-static-ip --static-ip-name <ip name>`; a detached static IP is billed.

## Verify and hand off

From outside AWS, `ssh` works, and after deployment `dig @<ip> <relay domain> NS` and `curl -fsS https://<relay domain>/api/healthz` succeed. A timeout with the container healthy almost always means a missing security group rule or Lightsail port.

Then continue with the `portal-relay` skill from **Verify the host**, not from **Deploy**: a fresh image may lack Docker and Compose v2, and that step checks and, with approval, installs them. Use this host's public address as the glue address. The NS and glue records come before **Deploy**, at the common skill's **Delegate DNS** step, because the relay's first start needs them to issue its certificate; the DS comes after **Deploy**, at **Publish the DS**. Report the resources created, the account and region, the estimated monthly cost, and the rollback commands.

Portal can also use Route 53 as its ACME DNS provider (`ACME_DNS_PROVIDER=route53`); that is relay configuration covered by the configuration reference, not by this skill.

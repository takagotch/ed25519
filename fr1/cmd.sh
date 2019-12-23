ssh-keygen -t ed25519 -N "" -f ~/.ssh/github -C tky@gmail.com
// ~/.ssh/github.pub
ssh-ed25519 xxx

// ~/.ssh/github
---BEGIN OPENSSH PRIVATE KEY---
xxx
---END OPENSSH PRIVATE KEY---

pbcopy < ~/.ssh/github.pub

vi ~/.ssh/config
Host *
  StrictHostKeyChecking no
  UserKnowHostsFile=/dev/null
  ServerAliveInterval 15
  ServerAliveCountMax 30
  AddKeysToAgent yes
  UseKeychain yes
  IdentitiesOnly yes

Host github.com
  HostName github.com
  IdentityFile ~/.ssh/github
  User git
  LogLevel QUIET

ssh -T github.com




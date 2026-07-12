include profile::baseline

$deploy_token = lookup('profile::deploy_token')

profile::application { 'production':
  environment => 'production',
}

file { '/tmp/installer.sh':
  ensure => file,
  source => 'http://downloads.example.com/installer.sh',
  mode   => '0777',
}

user { 'deploy':
  ensure => present,
}

exec { 'database migration':
  command => '/srv/migrate',
  notify  => Service['application'],
}

service { 'application':
  ensure => stopped,
}

@@ssh_authorized_key { 'deploy-node':
  ensure => present,
  user   => 'deploy',
  type   => 'ssh-ed25519',
  key    => 'AAAAexample',
}

Ssh_authorized_key <<| |>>

schedule { 'nightly':
  period => daily,
  range  => '2:00 - 4:00',
}

notify { 'rollout configured': }

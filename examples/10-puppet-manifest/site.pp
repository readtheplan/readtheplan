package { 'nginx':
  ensure => installed,
}

service { 'nginx':
  ensure => running,
  enable => true,
}

exec { 'database migration':
  command => './manage.py migrate',
}

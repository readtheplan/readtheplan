default['fixture']['port'] = 8443
override['fixture']['api_token'] = 'fixture-secret-value'
default['fixture']['external'] = data_bag_item('fixture', 'runtime')

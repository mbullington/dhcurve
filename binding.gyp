{
    'targets': [{
		'target_name': 'dhcurve',
		'sources': [ 'src/dhcurve.cc' ],
		'include_dirs': [
            "<!(node -e \"require('nan')\")"
        ],
        'conditions': [
			[ 'node_shared_openssl=="false"', {
				'include_dirs': ['<(node_root_dir)/deps/openssl/openssl/include']
			}]
		]
	}]
}

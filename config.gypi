{
    'target_defaults': {
        'default_configuration': 'Release',
        'configurations': {
            'Debug': {
                'cflags': [
                    '-Werror', '-g'
                ],
            },
            'Release': {
                'cflags': [
                    '-O3'
                ],
            },
        },
        'cflags': [
            '-Wall', '-Wextra'
        ],
    },
}

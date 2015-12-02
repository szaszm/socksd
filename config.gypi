{
    'target_defaults': {
        'default_configuration': 'Release',
        'configurations': {
            'Debug': {
                'cflags': [
                    '-Werror', '-g'
                ],
                'defines': [ 'DEBUG' ],
            },
            'Release': {
                'cflags': [
                    '-O3'
                ],
                'defines': [ 'NDEBUG' ],
            },
        },
        'cflags': [
            '-Wall', '-Wextra', '-std=c11'
        ],
        'defines': [ '_POSIX_SOURCE' ],
    },
}

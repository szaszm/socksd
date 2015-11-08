{
    'includes': [
        'config.gypi',
    ],
    'targets': [
        {
            'target_name': 'socksd',
            'type': 'executable',
            'sources': [
                'src/main.c'
            ],
            'libraries': [
                '-luv',
            ],
            'configurations': {
                'Debug':{},
                'Release':{},
            },
        },
    ],
}

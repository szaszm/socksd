{
    'includes': [
        'config.gypi',
    ],
    'targets': [
        {
            'target_name': 'socksd',
            'type': 'executable',
            'sources': [
                'src/main.c',
                'src/Client.c',
                'src/Logger.c'
            ],
            'libraries': [
                #'-luv',
            ],
            'configurations': {
                'Debug':{},
                'Release':{},
            },
        },
    ],
}

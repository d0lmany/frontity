<?php
# 3 API modes default: dev, test, prod (you can create more if you need)
return [
    'dev' => [
        # rules - behavior management
        'rules' => [
            'env' => 'file', # how to fill in $_ENV: from .env - 'file', from environment - 'env'
            'ignore_roles' => false, # ignore the role system
            'ignore_validations' => false, # ignore the validation system
            'user_entity_fields' => [ # instructions for the token and role system in the "myProperty => yourValue" format (leave token_timer empty if not required)
                'entity' => 'users', # entity with required fields
                'role' => 'role', # role field
                'login' => 'email', # login field
                'password' => 'password', # password field
                'token' => 'token', # token field
                'token_timer' => 'token_expires_at' # token expires at __ field
            ],
            'allow_entities_method' => true, # allow "ENTITIES" method, like 'show databases' in SQL
            'logging' => true, # if you need logging
            'logging_file_path' => 'log.txt' # path for log file
        ],
        'entities' => [ # rules for entities, customize for each entity as you need
            'users' => [ # name of entity
                'hidden_fields' => ['password', 'token'], # which fields should be hidden from the response, add/remove in array
                'hash' => [ # hashing settings: field, method, function attribute
                    ['field' => 'email', 'method' => 'openssl', 'attribute' => 'aes-256-cbc'],
                    ['field' => 'password', 'method' => 'password_hash', 'attribute' => PASSWORD_DEFAULT],
                    ['field' => 'birthdate', 'method' => 'hash', 'attribute' => 'sha256']
                ],
                'validations' => [ # field validation settings
                    'email' => [ # name of field
                        'required' => true,
                        'type' => 'string',
                        'regex' => FILTER_VALIDATE_EMAIL # if value is number - validate from function 'filter'
                    ],
                    'password' => [
                        'required' => true,
                        'type' => 'string',
                        'regex' => '/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)[A-Za-z\d]{8,}$/' # if value is regular expression - validate from preg* function
                    ],
                    'age' => [ # min/max for number types
                        'type' => 'number',
                        'min' => 18,
                        'max' => null # leave null if there are no restrictions
                    ]
                ]
            ],
            'posts' => [
                'owner_field' => ['users', 'id', 'user_id'] # an array to check whether the user can make changes to the entities. 1 value is the parent entity, 2 value is the parent key with the role field, 3 value is the reference to the parent key
            ]
        ],
        'roles' => [ # the role system, customize for each entity/role as you need. methods: getById, getAll, post, delete, put, patch
            'user' => [ # name of role (stored in the "role" field)
                'posts' => ['*'] # rules for the entity => array with allowed methods
            ],
            'hater' => [
                'posts' => ['getById', 'getAll']
            ]
        ],
        'headers' => [ # array of headers, customize as you need
            'Content-Type: application/json; charset=utf-8',
            'Access-Control-Allow-Methods: GET, POST, DELETE, PUT, PATCH, OPTIONS',
            'Access-Control-Allow-Headers: Content-Type, Authorization',
            'X-Content-Type-Options: nosniff',
            'X-Frame-Options: DENY',
            'Strict-Transport-Security: max-age=31536000; includeSubDomains',
            "Content-Security-Policy: default-src 'self'",
            "X-XSS-Protection: 1; mode=block",
            #'Access-Control-Allow-Origin: *',
        ],
        'forbidden_cors' => [ # which entities should be forbidden, like 'entity => <array of methods>', write '*' if you need full hide
            'entity' => ['*'],
            'topics' => ['put', 'patch']
        ],
        'filepaths' => [ # paths to save files
            'file' => 'content' # 'your-domain.org/api/file' => 'www/api/content/'
        ]
    ],
    'test' => [
        //
    ],
    'prod' => [
        //
    ]
];
<?php
return [
    'dev' => [ # APP_MODE
        # rules - behavior management
        'rules' => [ # REQUIRED
            'ignore_roles' => false, # ignore the role system
            'decrypt_for_request' => true, # decrypt openssl data from db
            'ignore_ownership' => false, # ignore ownership checking
            'ignore_validations' => false, # ignore the validation system
            'user_entity_fields' => [ # instructions for the token and role system in the "myProperty => yourValue" format (leave token_timer empty if not required)
                'entity' => 'users', # entity with required fields
                'role' => 'role', # role field
                'login' => 'email', # login field
                'password' => 'password', # password field
                'token' => 'token', # token field
            ],
            'logging' => false, # if you need logging
            'logging_file' => 'log.log', # path for log file
            'database' => 'mysql', # mysql or mariadb driver p.s. not tested
        ],
        'entities' => [ # rules for entities, customize for each entity as you need
            'users' => [ # name of entity
                'hidden_fields' => ['password', 'token'], # which fields should be hidden from the response, add/remove in array
                'hash' => [ # hashing settings: field, method, function attribute
                    ['field' => 'sensitive', 'method' => 'openssl', 'attribute' => 'AES-256-CBC'],
                    ['field' => 'password', 'method' => 'password_hash', 'attribute' => PASSWORD_DEFAULT],
                    # ['field' => 'birthdate', 'method' => 'hash', 'attribute' => 'sha256']
                ],
                'validations' => [ # field validation settings
                    'email' => [ # name of field
                        'required' => true,
                        'type' => 'string', # current types: string, int, float, double, bool, array
                        'regex' => FILTER_VALIDATE_EMAIL # if value is number - validate from function 'filter'
                    ],
                    'password' => [
                        'required' => true,
                        'type' => 'string',
                        'regex' => '/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)[A-Za-z\d]{8,}$/' # if value is regular expression - validate from preg_match function
                    ],
                    'age' => [ # min/max for number types
                        'type' => 'int',
                        'min' => 18,
                        'max' => null # set null if there are no restrictions or unset
                    ]
                ]
            ],
            'posts' => [
                'owner_field' => 'user_id', # setting by which field in this entity to search for the owner in the users entity
                'validations' => [
                    'text' => [
                        'required' => true,
                        'type' => 'string',
                        'regex' => 'htmlspecialchars' # applies the 'htmlspecialchars()' function to a variable
                    ]
                ]
            ],
            'numbers' => [
                'validations' => [
                    'number' => [
                        'type' => 'int',
                        'min' => 5,
                        'max' => 10
                    ]
                ]
            ]
        ],
        'roles' => [ # the role system, customize for each entity/role as you need. methods: getById, getAll, post, delete, put, patch, auth, serviceToken, postFiles, deleteFiles
            'user' => [ # name of role (stored in the "role" field)
                'posts' => ['getById', 'getAll', 'post', 'delete', 'put', 'patch', 'auth', 'serviceToken', 'postFiles'], # rules for the entity => array with allowed methods
                'users' => ['getAll', 'getById']
            ],
            'hater' => [
                'posts' => ['getById', 'getAll'],
                'users' => ['getAll', 'getById']
            ],
            'system' => [
                'users' => ['*'],
                'topics' => ['*'],
                'posts' => ['*'],
                'numbers' => ['*']
            ],
            'admin' => [
                'posts' => ['*'],
                'numbers' => ['*'],
                'users' => ['*'],
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
            "Access-Control-Allow-Origin: *",
            "Allow: GET, POST, DELETE, PUT, PATCH, OPTIONS"
        ],
        'forbidden_cors' => [ # which entities should be forbidden, like 'entity => <array of methods>', write '*' if you need full hide
            'topics' => ['put', 'patch']
        ],
        'filepaths' => [ # paths to save files
            'content' => [ # web path like 'your-domain.org/<content>'
                'path' => 'folder', # folder on server like 'www/<content>'
                'mimeTypes' => ['image/jpeg', 'image/png'], # allowed mime types for files
                'min_size' => null, # min size of uploaded file, set 'null' if there are no restrictions or unset
                'max_size' => 1024 * 1024 * 2, # max size of uploaded file, set 'null' if there are no restrictions or unset
                'overwrite' => false, # overwrite the file if there is a name conflict. if 'false', a random string is added to the name.
            ]
        ]
    ],
    'test' => [
        //
    ],
    'prod' => [
        //
    ],
    'maintenance' => false, # returns 503 (the service is temporarily unavailable)
    'gone' => false, # returns 410 (the service is destroyed)
];
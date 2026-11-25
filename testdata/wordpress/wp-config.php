<?php
// ** Database settings ** //
define( 'DB_NAME', 'example_db' );
define( 'DB_PASSWORD', 'not-a-real-password' );

define( 'AUTH_KEY',         'put your unique phrase here' );
define( 'SECURE_AUTH_KEY',  'put your unique phrase here' );
define( 'LOGGED_IN_KEY',    'k2//x/*y9-random-value-with-slashes' );
define( 'NONCE_KEY',        getenv('NONCE_KEY') );
define( 'AUTH_SALT',        'a-long-random-value-1' );
define( 'SECURE_AUTH_SALT', 'a-long-random-value-2' );
define( 'LOGGED_IN_SALT',   'a-long-random-value-3' );
// define( 'NONCE_SALT', 'commented out' );

define( 'WP_DEBUG', true );
$table_prefix = 'wp_';

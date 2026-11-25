server {
    listen 443 ssl;
    server_name www.example.com;
    root /var/www/example.com;
    ssl_certificate certs/example.com.pem;
    ssl_certificate_key certs/example.com.key;
    ssl_certificate $ssl_cert_from_map;
    add_header X-Content-Type-Options nosniff always;
    location /files/ {
        autoindex on;
    }
    location ~ \.php$ {
        fastcgi_pass unix:/run/php/php7.4-fpm.sock;
    }
}

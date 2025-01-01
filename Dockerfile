FROM php:8.4-cli

# Install PHP extensions
RUN docker-php-ext-configure sockets \
    && docker-php-ext-install -j$(nproc) \
    sockets

WORKDIR /app

CMD ["tail", "-f", "/dev/null"] 
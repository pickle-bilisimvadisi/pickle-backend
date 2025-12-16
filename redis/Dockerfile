# Resmi Redis imajını temel alın
FROM redis:latest

# Yerel redis.conf dosyasını konteynıra kopyalayın
COPY redis.conf /usr/local/etc/redis/redis.conf

# Redis'i özel yapılandırma dosyasıyla çalıştırın
CMD ["redis-server", "/usr/local/etc/redis/redis.conf"]

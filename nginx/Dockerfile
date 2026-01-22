FROM nginx as nginx-src

RUN rm /etc/nginx/conf.d/default.conf

COPY nginx.conf /etc/nginx/conf.d/

COPY certs /etc/nginx/certs

# RUN ls /etc/nginx 
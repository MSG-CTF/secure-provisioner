FROM busybox:1.37.0@sha256:9db7b59979c38555a39def84a31fb98b5296952f9e3afd4f6f11f05b07adfab0
COPY index.html /www/index.html
USER 10001:10001
EXPOSE 8080 9000
CMD ["sh", "-c", "httpd -p 9000 -h /www; exec httpd -f -p 8080 -h /www"]

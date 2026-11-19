FROM alpine:3.20
RUN apk add --no-cache openssh \
 && ssh-keygen -A \
 && adduser -D admin_repo \
 && echo "admin_repo:Lab-Atenea-2026" | chpasswd
# La configuracion de sshd se monta desde docker-compose (inicial o de cierre)
EXPOSE 22
CMD ["/usr/sbin/sshd", "-D", "-e"]

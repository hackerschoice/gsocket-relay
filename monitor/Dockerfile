FROM ubuntu:latest

COPY heartbeat.sh funcs /
COPY gsocket_latest_all.deb /tmp
RUN apt update -y && \
	apt install -y --no-install-recommends \
	openssl && \
	apt clean && \
	rm -rf /var/lib/apt/lists/ && \
	dpkg -i --ignore-depends sshfs /tmp/gsocket_latest_all.deb && \
	echo DONE

ENTRYPOINT ["/heartbeat.sh"]
CMD ["gs1.thc.org", "gs2.thc.org", "gs3.thc.org"]

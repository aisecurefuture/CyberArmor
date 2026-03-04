FROM envoyproxy/envoy:v1.31-latest

COPY envoy.yaml /etc/envoy/envoy.yaml
COPY filters/ /etc/envoy/filters/

EXPOSE 10000 10001 9901
CMD ["/usr/local/bin/envoy", "-c", "/etc/envoy/envoy.yaml"]

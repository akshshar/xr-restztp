FROM ubuntu:16.04

RUN apt-get update && apt-get install -y vim git python3 python3-pip && pip3 install flask flask-restful requests
RUN git clone https://github.com/akshshar/xr-restztp.git /root/xr-restztp/ && \
    mkdir -p /usr/local/lib/xr-restztp && \
    mv /root/xr-restztp/lib/restful_ztp.py /usr/local/lib/xr-restztp/ && \
    mv /root/xr-restztp/lib/config.json /usr/local/lib/xr-restztp && \
    rm -r /root/xr-restztp
EXPOSE 5000

CMD ["/usr/bin/python3", "/root/xr-restztp/lib/restful_ztp.py"]

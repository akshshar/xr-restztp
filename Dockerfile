FROM ubuntu:16.04

RUN apt-get update && apt-get install -y vim git python3 python3-pip && pip3 install flask flask-restful requests
RUN git clone https://github.com/akshshar/xr-restztp.git /root/xr-restztp/ && \
    mv /root/xr-restztp/lib/ /usr/local/lib/xr-restztp/ && \
    rm -r /root/xr-restztp
EXPOSE 5000

CMD ["/usr/bin/python3", "/usr/local/lib/xr-restztp/restful_ztp_hook.py"]

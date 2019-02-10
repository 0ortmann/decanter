FROM debian:stretch

RUN apt-get update && apt-get -y install \
    python3 \
    python3-pip \
    --no-install-recommends && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pip3 install --upgrade \
    wheel \
    setuptools

WORKDIR /opt/decanter
ENV PYTHONPATH $PYTHONPATH:/opt/decanter

COPY test-data ./test-data

COPY requirements.txt .
RUN pip3 install -r requirements.txt

COPY bro_parser.py \
     decanter_new.py \
     detection.py \
     evaluation_utils.py \
     fingerprint.py \
     label_generation.py \
     main.py ./

CMD python3 main.py --training test-data/user/log/riccardo_linux_training_16-01.log --testing test-data/malware/exiltration_logs/FAREIT_25.pcap.decanter.log -o 0
FROM jupyter/scipy-notebook:latest

LABEL maintainer="José Faria <jose.faria@isr.uc.pt>"

RUN DEBIAN_FRONTEND=noninteractive apt-get install --yes --no-install-recommends tshark
RUN mamba install --quiet --yes pyshark
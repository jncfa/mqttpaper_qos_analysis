FROM jupyter/scipy-notebook:latest

LABEL maintainer="José Faria <jose.faria@isr.uc.pt>"

USER root

RUN DEBIAN_FRONTEND=noninteractive apt-get install --yes --no-install-recommends tshark
RUN mamba install --quiet --yes pyshark

USER ${NB_UID}
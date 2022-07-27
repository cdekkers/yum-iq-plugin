FROM centos:7

RUN yum install -y java-11-headless git
RUN mkdir /usr/lib/nexus-iq-cli
RUN curl -L -o /usr/lib/nexus-iq-cli/nexus-iq-cli.jar https://download.sonatype.com/clm/scanner/latest.jar

CMD ["/bin/bash"]
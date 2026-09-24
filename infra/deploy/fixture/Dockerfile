FROM python:3.12-alpine
ARG REVISION
LABEL org.opencontainers.image.source="https://github.com/ColorlessCube/ass"
LABEL org.opencontainers.image.revision=$REVISION
WORKDIR /srv
RUN printf 'deployment fixture\n' > index.html
USER 10001:10001
CMD ["python", "-m", "http.server", "8080"]

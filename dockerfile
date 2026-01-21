FROM python:3.13 as python-src
WORKDIR /usr/local/odsi_app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

RUN apt update
RUN apt install nginx

COPY src ./src 
EXPOSE 8080


# FROM nginx AS nginx-img

# COPY --from=python-src 

CMD
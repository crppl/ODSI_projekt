FROM python:3.11 AS python-src
WORKDIR /odsi_app

COPY . /odsi_app

RUN pip install --no-cache-dir uwsgi
RUN pip install --no-cache-dir -r requirements.txt

COPY src ./src 
EXPOSE 2137


# FROM nginx AS nginx-img

# COPY --from=python-src 
 
CMD ["uwsgi", "app.ini"]
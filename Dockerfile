FROM python:3.12-alpine3.20

LABEL maintainer="sudeep.bogati@greentick.com.np"
LABEL version="1.0"

WORKDIR /gkavach-dwm

COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt


COPY . .
# RUN python manage.py makemigrations
# RUN python manage.py migrate
RUN python manage.py collectstatic --noinput
EXPOSE 8000

ENV DJANGO_SETTINGS_MODULE=DWmonitoring.settings

CMD ["gunicorn", "--bind", "0.0.0.0:8000", "DWmonitoring.wsgi:application"]

FROM python:3

WORKDIR /urt/src/app

COPY requirements.txt ./

RUN pip install --upgrade pip

RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN pip install ./en_core_web_sm-3.0.0.tar.gz

CMD ["python", "app.py"]



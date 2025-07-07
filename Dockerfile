# Dockerfile

FROM python:3.9

# Set working directory inside container
WORKDIR /app

# Copy all files from current directory into container
COPY . /app

# Install dependencies
RUN pip install --upgrade pip
RUN pip install -r requirements.txt

# Expose Flask app port
EXPOSE 5050

# Run the Flask app
CMD ["python", "app.py"]

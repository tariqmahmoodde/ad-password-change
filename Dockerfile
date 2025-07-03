# Use an official Python runtime as a parent image
FROM python:3.9-slim

# Set the working directory in the container
WORKDIR /app

# Copy the requirements file into the container at /app
COPY requirements.txt .

# Install any needed packages specified in requirements.txt
# Use --no-cache-dir to reduce image size and --trusted-host to avoid SSL issues in some networks
RUN pip install --no-cache-dir --trusted-host pypi.python.org -r requirements.txt

# Copy the rest of the application code into the container at /app
COPY . .

# Make port 5000 available to the world outside this container
EXPOSE 5000

# Define environment variable to tell Flask the entry point of the application
ENV FLASK_APP=app.py

# Run the app using gunicorn, a production-ready WSGI server.
# The environment variables for AD connection will be passed in at runtime.
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "app:app"]
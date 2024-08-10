# Use an official Python runtime as a parent image
FROM python:3.12

# Set environment variables to avoid prompts during GDAL installation
ENV DEBIAN_FRONTEND=noninteractive

# Set the working directory in the container
WORKDIR carapi

# Copy the requirements file into the container
COPY requirements.txt ./

# Install any needed packages specified in requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application code into the container
COPY .. .

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

# Expose the port the app runs on
EXPOSE 8000

# Define the default command to run when starting the container
CMD ["sh", "-c", "python manage.py migrate && python manage.py runserver 0.0.0.0:8000"]

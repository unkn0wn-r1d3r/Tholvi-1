# Step 1: Start with a base Python image
FROM python:3.9-slim

# Step 2: Set the working directory inside the container
WORKDIR /app

# Step 3: Copy the Flask app files into the container
COPY . /app

# Step 4: Install the necessary Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Step 5: Expose the Flask app's port (5000 by default)
EXPOSE 5000

# Step 6: Set the environment variable for Flask to run in production mode
ENV FLASK_APP=app.py
ENV FLASK_ENV=production

# Step 7: Run the Flask application
CMD ["flask", "run", "--host=0.0.0.0"]

# Use official Playwright image with all dependencies
FROM mcr.microsoft.com/playwright:v1.44.0-jammy

# Set working directory
WORKDIR /app

# Copy everything to container
COPY . .

# Install dependencies
RUN npm install

# Expose the port your app runs on
EXPOSE 3001

# Start the server
CMD ["node", "index.js"]

# Pick a node version, 
FROM node:lts


# Set the working directory inside the container. Think of this as a virtual enviornment.
WORKDIR /app


# Copy package.json and package-lock.json (if available)
COPY package*.json ./

# Install dependencies
RUN npm install 

# Copy the rest of the application code
COPY . .


# Expose the port the app runs on
EXPOSE 3000

# Define the command to run the application
CMD ["node", "server.js"]

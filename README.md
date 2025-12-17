Middle Security Forum Site

Server Accessible through: https://bhbuilders.org

Database Schema

  - Three tables implemented using SQLite3 with persistent storage:

      -users

      -login attempts

      -comments

  - These are used for security and content tracking.

Security Features Implemented

    - Account lockout after too many failed login attempts

    - Server configured with HTTPS via Nginx Proxy Manager SSL

    - Passwords hashed using Argon2

    - Passwords can be reset through the profile page

Known Limitations or Issues

    - Socket capabilities have been removed due to server instability

    - No email functionality implemented

User Experience

    - Users can change their password, display name, and display color in the profile page (“the Abode”)

    - Comments that are too large will be truncated; users can click “Read More” to view full content

    - Users can log out from the navigation bar

Routes

    /register

    /login

    /logout

    /feed

    /user

    /user/password

    /user/display-name

    /user/profile

    /comment

Instructions (Docker Prerequisite)

Clone the repository:

    git clone <repo-url>
    cd WebDevForum


Build and run the Docker containers:

    docker compose up --build


Navigate to http://localhost:3000 in your browser.

When finished, shut down the containers:

    docker compose down


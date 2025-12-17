middle security forum site
Server Accessible through: https://bhbuilders.org

– Database schema

Three tables implemented through sqlite3 with persistent storage:
users
login attempts
comments
Used for security and tracking content
– Security features implemented Account lockout after too many failed attempts Server is set up with https through Nginx Proxy Manager ssl Passwords are hashed with argon2 passwords can be reset through profile page

– Known limitations or issues - in the interest of time (and because my server kept breaking) socket capabilities have been scratched - There is also no email functionality

User Experience
Users can change password, display name, and display color in profile page ("the Abode")
comments that are too large will be truncated, users can click "read more" to view large comments
User can log out from nav bar
ROUTES: /register /login /logout /feed /user /user/password /user/display-name /user/profile /comment

Instructions (docker prereq):

Clone repo
cd WebDevForum
run "docker compose up --build"
navigate to http://localhost:3000 on browser
when finished "docker compose down"

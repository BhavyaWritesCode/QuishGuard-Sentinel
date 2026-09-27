# QuishGuard-Sentinel-Project
1- .\mvnw.cmd clean install
2- $env:JWT_SECRET="YOUR_JWT_SECRET_FROM_ENV"
3- $env:DB_USERNAME="postgres"
4 - $env:DB_PASSWORD="YOUR_DB_PASSWORD_FROM_ENV"
5 - .\mvnw.cmd spring-boot:run
new terminal
6- curl http://localhost:8080/actuator/health
7 - curl.exe -X POST "http://localhost:8080/api/scan/upload" -F "file=@C:\Users\bhavy\Pictures\Screenshots\Screenshot 2026-08-22 010522.png"
8 - curl.exe -X POST "http://localhost:8080/api/scan/upload" -F "file=@C:\Users\bhavy\Pictures\Screenshots\Screenshot 2026-08-22 012427.png"
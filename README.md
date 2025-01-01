# Implementing the MySQL Protocol in Pure PHP: Are You Ready to Dive Deep?

This repository contains a source code for the article "Implementing the MySQL Protocol in Pure PHP: Are You Ready to Dive Deep?".

## Project Structure

```
.
├── README.md
├── client.php         # MySQL client in pure PHP
├── demo.php           # Main PHP script that queries the database
├── docker-compose.yml # Docker compose configuration
├── Dockerfile        # PHP CLI container configuration
└── test-data.sql    # Initial database setup and data
```

## Prerequisites

- Docker
- Docker Compose

## Setup and Running

1. Clone the repository:
```bash
git clone <repository-url>
cd <project-directory>
```

2. Start the Docker containers:
```bash
docker-compose up -d --build
```

This will:
- Start a MySQL database container
- Initialize the database with test data
- Start an Adminer container for database management
- Start a PHP CLI container

3. Run the demo script:
```bash
docker-compose exec php-cli php demo.php
```

## Container Details

### MySQL Database
- Host: db
- Port: 3306
- Database: exampledb
- Username: exampleuser
- Password: examplepassword

### Adminer (Database Management)
- Access URL: http://localhost:8080
- System: MySQL
- Server: db
- Username: exampleuser
- Password: examplepassword
- Database: exampledb

### PHP CLI
- PHP Version: 8.4
- Installed extensions: sockets

## Database Structure

The database includes a single table `foo` with the following structure:

```sql
CREATE TABLE `foo` (
                       `id` int NOT NULL AUTO_INCREMENT,
                       `text` text,
                       PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

INSERT INTO `foo` (`id`, `text`) VALUES (1, 'test'), (2, 'next');
```

Initial test data:
- id: 1, text: "test"
- id: 2, text: "next"

## Development

The project uses volume mounts for development:
- The MySQL data is stored in a tmpfs volume for fast testing
- The application code is mounted into the PHP container at `/app`
- The database initialization script is mounted at container startup

## Troubleshooting

1. If the database connection fails, ensure:
   - All containers are running (`docker-compose ps`)
   - The MySQL container is fully initialized
   - The connection credentials match those in docker-compose.yml

2. To reset the environment:
```bash
docker-compose down
docker-compose up -d --build
```

3. To view logs:
```bash
docker-compose logs db      # MySQL logs
docker-compose logs php-cli # PHP container logs
```


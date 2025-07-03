# AD Password Change Web App

A simple Flask web application that allows Active Directory users to change their own passwords, even if they have expired.

## Features

-   **Self-Service Password Reset:** Users can change their AD password without administrator intervention.
-   **Expired Password Changes:** Supports changing passwords that have already expired by using an admin bind to perform the final change.
-   **Client-Side Validation:** Real-time password complexity checks and hints for a better user experience.
-   **Secure Configuration:** All sensitive AD credentials and settings are loaded from environment variables, not hardcoded.
-   **Containerized:** Comes with a `Dockerfile` and `docker-compose.yml` for easy, consistent deployment.

## Prerequisites

-   Docker
-   Docker Compose (usually included with Docker Desktop)

## Getting Started

Follow these steps to get the application running locally.

### 1. Clone the Repository

If you have this project in a git repository, clone it first.

```bash
git clone <your-repo-url>
cd <repo-directory>
```

### 2. Configure Environment Variables

The application is configured using an `.env` file. Create a file named `.env` in the project root by copying the example:

```bash
cp .env.example .env
```

Now, open the `.env` file with a text editor and fill in your Active Directory details.

### 3. Run the Application with Docker Compose

The easiest way to run the application is with Docker Compose. This command will build the Docker image and start the container in the background.

```bash
docker-compose up -d --build
```

The application will be available at `http://localhost:5000`.

To view logs:
```bash
docker-compose logs -f
```

To stop the application:
```bash
docker-compose down
```

## Environment Variables

The following environment variables are required in your `.env` file:

| Variable | Description | Example |
| :--- | :--- | :--- |
| `SECRET_KEY` | A secret key used by Flask for signing session cookies. Should be a long, random string. | `super-secret-random-string` |
| `AD_SERVER_IP` | The IP address or hostname of your Active Directory Domain Controller. | `192.168.1.10` |
| `AD_DOMAIN` | The short NetBIOS name of your AD domain. | `CONTOSO` |
| `AD_FQDN` | The Fully Qualified Domain Name of your AD domain. | `contoso.local` |
| `AD_ADMIN_USERNAME` | The username of an AD account with permissions to reset user passwords. | `svc_ad_admin` |
| `AD_ADMIN_PASS` | The password for the admin/service account. | `P@sswordForSvcAccount!` |

## Technology Stack

-   **Backend:** Flask
-   **LDAP Communication:** ldap3
-   **Frontend:** HTML, Bootstrap 5, JavaScript
-   **Containerization:** Docker, Docker Compose
-   **WSGI Server:** Gunicorn
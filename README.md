

Univa Test API Documentation
===========================

This project is a Symfony 7 application with API endpoints documented using NelmioApiDocBundle. Follow the steps below to set up the project and explore the API documentation.

Setup Instructions
------------------

### 1\. Create a Database

Ensure you have a MySQL database set up. You'll need the database name and credentials for the `.env.local` file.

### 2\. Create `.env.local` File

Create a `.env.local` file in the root directory of the project based on the provided `.env` file. Update the `DATABASE_URL` with your PostgreSQL database details.

### 3\. Install Dependencies

Run the following command to install the project dependencies:

```bash
composer install
```
If the installation fails due to missing database tables, proceed to run the migrations and then run again the composer install:

```bash
php bin/console doctrine:migrations:migrate
```

### 4\. Run Symfony Server

If you have Symfony CLI installed, you can start the Symfony server using the following command:

```bash
symfony serve -d
```

### 5\. Explore API Documentation

Once the server is running, you can access the API documentation at `http://127.0.0.1:8000/apidoc/doc`. If you're using a different hostname or port, adjust the URL accordingly.

### 6\. Register and Authenticate Users

*   Use the `/api/register` endpoint to register a new user. This endpoint creates a `ROLE_USER` user.
*   Use the `/api/login` endpoint to log in and obtain an authentication token.
*   Authenticate with the obtained token by clicking the "Authorize" button at the top right corner of the API documentation. Enter `Bearer YOUR_TOKEN` and click "Authorize".

### 7\. Additional Notes

*   Deleting the admin user is not recommended. If accidentally deleted, you can recreate it using the following command:

```bash
php bin/console CreateAdminUserCommand --email=youremailaddress --password=yourpassword
```

*   For detailed API documentation, refer to the Swagger UI provided at `http://127.0.0.1:8000/apidoc/doc`.

Live Demo
---------

A live demo of this project is available at [https://univa.atomoweb.com/apidoc/doc](https://univa.atomoweb.com/apidoc/doc).

Repository
----------

The source code for this project is available on GitHub: [https://github.com/luisatomo/univa-test-sv7/](https://github.com/luisatomo/univa-test-sv7/)
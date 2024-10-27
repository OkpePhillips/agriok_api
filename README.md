
# Farming Management API

This API is designed to support a comprehensive farming management system, allowing users to manage transactions, farmlands, insights, product purchases, and personal blog-like posts. The API includes user authentication, role-based permissions, and CRUD operations for key models.

## Table of Contents

- [Features](#features)
- [Setup Instructions](#setup-instructions)
- [API Endpoints](#api-endpoints)
- [Permissions](#permissions)
- [Models](#models)

---

### Features

- **User Management**: User authentication and role-based access.
- **Farmland and Insights Management**: Create, retrieve, update, and delete farmlands and ML-generated insights.
- **Product Purchases and Transactions**: Manage carts, purchase products, and automatically track transactions.
- **Blog-like Posting**: Users can create, retrieve, update, and delete posts.
- **Data Persistence**: Each model is saved and managed through the Django ORM, using PostgreSQL as the primary database.

---

### Setup Instructions

1. **Clone the repository:**
   ```bash
   git clone <repository-url>
   cd <repository-directory>
   ```

2. **Install dependencies**:
   Make sure you have [Python 3.x](https://www.python.org/downloads/) installed. Use `pip` to install the requirements:
   ```bash
   pip install -r requirements.txt
   ```

3. **Set up PostgreSQL**:
   - Install PostgreSQL and create a database for the project.
   - Configure your database settings in `settings.py`.

4. **Environment Variables**:
   Configure a `.env` file with the necessary variables:
   ```
   SECRET_KEY=your_secret_key
   DATABASE_NAME=your_database
   DATABASE_USER=your_user
   DATABASE_PASSWORD=your_password
   ```

5. **Run Migrations**:
   ```bash
   python manage.py makemigrations
   python manage.py migrate
   ```

6. **Create a Superuser**:
   ```bash
   python manage.py createsuperuser
   ```

7. **Start the Development Server**:
   ```bash
   python manage.py runserver
   ```

---

### API Endpoints

Below is a summary of key endpoints.

| HTTP Method | Endpoint                        | Description                                       |
|-------------|---------------------------------|---------------------------------------------------|
| POST        | `/api/login/`              | User login                                        |
| POST        | `/api/register/`           | Register a new user                               |
| GET         | `/api/farmlands/`               | List all farmlands for the authenticated user     |
| POST        | `/api/farmlands/`               | Create a new farmland                             |
| GET, PUT, DELETE | `/api/farmlands/<pk>/`     | Retrieve, update, or delete a specific farmland   |
| GET, POST   | `/api/transactions/`            | List or create a new transaction                  |
| GET, PUT, DELETE | `/api/transactions/<pk>/`  | Retrieve, update, or delete a specific transaction|
| GET, POST   | `/api/posts/`                   | List all posts or create a new post               |
| GET, PUT, DELETE | `/api/posts/<pk>/`         | Retrieve, update, or delete a specific post       |
| POST        | `/api/cart/add/`                | Add item to cart                                  |
| POST, DELETE | `/api/cart/remove/`            | Remove item from cart                             |
| GET         | `/api/orders/history/`          | View order history                                |
| POST        | `/api/orders/place/`            | Place an order                                    |

---

### Permissions

- **Authenticated Users**: Can create, view, update, and delete their own posts, transactions, farmlands, and insights.
- **Admin Users**: Can manage all users' data and have full access across endpoints.
- **Role-Based Access**: Specific endpoints (e.g., deleting or updating other users’ data) are restricted based on user role (admin vs. user).

---

### Models

1. **User (CustomUser)**:
   - Primary fields: `email`, `first_name`, `last_name`, `password`

2. **Farmland**:
   - Primary fields: `user`, `sensors`, `size`, `location`
   - Each farmland belongs to a specific user and may generate data from sensors located on the farmland.

3. **Insight**:
   - Primary fields: `title`, `content`, `date_posted`, `user`, `farmland`
   - Insights are generated from Machine Learning models based on data from sensors attached to a specific farmland.

4. **Product**:
   - Primary fields: `name`, `description`, `price`, `quantity`, `photo`

5. **Cart and CartItem**:
   - Primary fields: `user`, `product`, `quantity`

6. **Transaction**:
   - Primary fields: `user`, `items`, `amount`, `created_at`, `updated_at`
   - Automatically logs purchases and allows users to manually add transactions.

7. **Post**:
   - Primary fields: `title`, `content`, `user`, `created_at`, `updated_at`
   - A simple model for users to post blog-like entries.

---

### Future Enhancements

- **Notifications System**: Alert users of low stock, new insights, or significant changes in farmland metrics.
- **Enhanced Reporting**: Allow users to generate custom reports on transaction history or farmland productivity.
- **Analytics**: Visualize insights and trends based on sensor data to help users optimize their farms.

---

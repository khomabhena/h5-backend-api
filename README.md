# H5 Backend API

A Django Rest Framework API for managing H5 apps and processing SuperApp payment callbacks.

## 🚀 Features

- **H5 App Management**: Full CRUD operations for H5 apps
- **Payment Processing**: Handle SuperApp payment callbacks with encryption/decryption
- **MySQL Database**: Robust data storage with proper relationships
- **API Documentation**: Swagger/OpenAPI documentation
- **Logging**: Comprehensive logging for debugging and monitoring
- **CORS Support**: Cross-origin resource sharing configuration

## 📋 Requirements

- Python 3.8+
- MySQL 5.7+
- Django 4.2+
- Django Rest Framework 3.14+

## 🛠️ Installation

### 1. Clone the repository
```bash
git clone <repository-url>
cd h5-backend-api
```

### 2. Create virtual environment
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

### 3. Install dependencies
```bash
pip install -r requirements.txt
```

### 4. Database Setup

#### Create MySQL Database
```sql
CREATE DATABASE h5_backend_api CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
```

#### Configure Environment Variables
Copy `env.example` to `.env` and update the values:

```bash
cp env.example .env
```

Edit `.env` file:
```env
# Database Configuration
DB_NAME=h5_backend_api
DB_USER=root
DB_PASSWORD=your_mysql_password
DB_HOST=localhost
DB_PORT=3306

# Django Configuration
SECRET_KEY=your-secret-key-here
DEBUG=True
ALLOWED_HOSTS=localhost,127.0.0.1

# CORS Configuration
CORS_ALLOWED_ORIGINS=http://localhost:3000,http://127.0.0.1:3000
```

### 5. Run Migrations
```bash
python manage.py migrate
```

### 6. Create Superuser (Optional)
```bash
python manage.py createsuperuser
```

### 7. Start Development Server
```bash
python manage.py runserver
```

The API will be available at `http://localhost:8000/`

## 📚 API Documentation

### Swagger UI
- **URL**: `http://localhost:8000/swagger/`
- Interactive API documentation

### ReDoc
- **URL**: `http://localhost:8000/redoc/`
- Alternative API documentation

## 🔗 API Endpoints

### H5 Apps Management

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/h5-apps/` | List all H5 apps |
| POST | `/api/h5-apps/` | Create new H5 app |
| GET | `/api/h5-apps/{id}/` | Get H5 app details |
| PUT | `/api/h5-apps/{id}/` | Update H5 app |
| PATCH | `/api/h5-apps/{id}/` | Partial update H5 app |
| DELETE | `/api/h5-apps/{id}/` | Delete H5 app |
| GET | `/api/h5-apps/{id}/payments/` | Get payments for H5 app |

### Payments Management

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/payments/` | List all payments |
| POST | `/api/payments/` | Create new payment |
| GET | `/api/payments/{id}/` | Get payment details |
| GET | `/api/payments/stats/` | Get payment statistics |
| GET | `/api/payments/callback-logs/` | Get callback logs |

### SuperApp Integration

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/payment/callback/` | SuperApp payment callback |

## 🏗️ Database Schema

### H5App Model
- `id`: UUID primary key
- `name`: App name
- `description`: App description
- `app_key`: Unique app identifier
- `encryption_key`: Key for SuperApp integration
- `notify_url`: Callback URL
- `is_active`: Active status
- `created_at`, `updated_at`: Timestamps

### Payment Model
- `id`: UUID primary key
- `h5_app`: Foreign key to H5App
- `payment_ref`: Unique payment reference
- `amount`: Payment amount
- `currency`: Currency code
- `status`: Payment status (pending, completed, failed, etc.)
- `ciphertext`: Encrypted SuperApp data
- `decrypted_data`: Decrypted payment data
- `customer_email`, `customer_phone`: Customer information
- `order_id`: External order reference
- `created_at`, `updated_at`, `callback_received_at`: Timestamps

### PaymentCallbackLog Model
- `id`: UUID primary key
- `payment`: Foreign key to Payment
- `raw_payload`: Original callback data
- `response_sent`: Response sent to SuperApp
- `http_status`: HTTP status code
- `is_successful`: Success status
- `error_message`: Error details
- `received_at`: Timestamp

## 🔐 SuperApp Integration

### Payment Callback Flow

1. **Customer pays** in SuperApp
2. **SuperApp processes** payment internally
3. **SuperApp sends POST** to your `/api/payment/callback/` endpoint
4. **Your API decrypts** the ciphertext using the H5 app's encryption key
5. **Your API updates** the payment record
6. **Your API responds** with `{"code": "SUCCESS"}`

### Callback Request Format
```json
{
  "ciphertext": "base64_encoded_encrypted_data",
  "payment_ref": "unique_payment_reference",
  "timestamp": 1234567890
}
```

### Callback Response Format
```json
{
  "code": "SUCCESS"
}
```

## 🔍 Query Parameters

### H5 Apps
- `is_active`: Filter by active status (true/false)
- `search`: Search by name or app_key

### Payments
- `h5_app`: Filter by H5 app ID
- `status`: Filter by payment status
- `payment_ref`: Search by payment reference
- `start_date`, `end_date`: Filter by date range

### Statistics
- `h5_app_id`: Get stats for specific H5 app

## 🛡️ Security Considerations

1. **Environment Variables**: Store sensitive data in `.env` file
2. **Encryption Keys**: Keep H5 app encryption keys secure
3. **HTTPS**: Use HTTPS in production
4. **Authentication**: Implement proper authentication for production
5. **Rate Limiting**: Consider implementing rate limiting
6. **Input Validation**: All inputs are validated through serializers

## 📝 Logging

Logs are stored in the `logs/` directory:
- `django.log`: General application logs
- Console output for development

## 🧪 Testing

```bash
# Run tests
python manage.py test

# Run specific app tests
python manage.py test payments
```

## 🚀 Deployment

1. Set `DEBUG=False` in production
2. Configure proper `ALLOWED_HOSTS`
3. Use production database settings
4. Set up proper logging
5. Configure static files serving
6. Use environment variables for secrets

## 📞 Support

For questions or issues, please contact the development team.

## 📄 License

This project is licensed under the MIT License.


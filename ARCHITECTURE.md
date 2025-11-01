# H5 Backend API - Complete Architecture Documentation

This document provides a comprehensive guide to understanding, implementing, and replicating the H5 Backend API system. The architecture is designed to manage H5 mobile web applications and process encrypted payment callbacks from a SuperApp payment gateway.

## Table of Contents

1. [System Overview](#system-overview)
2. [Project Setup & Dependencies](#project-setup--dependencies)
3. [Database Architecture](#database-architecture)
4. [API Endpoints & Logic](#api-endpoints--logic)
5. [Encryption & Security](#encryption--security)
6. [Callbacks & Payment Processing](#callbacks--payment-processing)
7. [Configuration & Deployment](#configuration--deployment)
8. [Step-by-Step Implementation Guide](#step-by-step-implementation-guide)

---

## System Overview

### Purpose
The H5 Backend API is a Django REST Framework application that:
- Manages H5 mobile web applications with unique encryption keys
- Receives and processes encrypted payment callbacks from SuperApp
- Stores payment transactions with full audit trail
- Provides RESTful APIs for managing apps and payments

### Technology Stack
- **Backend Framework**: Django 4.2.7 / 5.2.7
- **API Framework**: Django REST Framework 3.14.0
- **Database**: MySQL (production) / SQLite (development)
- **Cryptography**: Python cryptography library (AES-256-GCM, AES-192-GCM)
- **API Documentation**: drf-yasg (Swagger/OpenAPI)
- **CORS**: django-cors-headers

### Key Features
- Full CRUD operations for H5 apps
- Encrypted callback processing from SuperApp
- Support for multiple encryption algorithms
- Comprehensive payment tracking and statistics
- Django Admin interface for data management
- Automatic callback payload logging
- Payment statistics and reporting

---

## Project Setup & Dependencies

### Directory Structure
```
h5-backend-api/
├── h5_backend_api/          # Django project settings
│   ├── __init__.py
│   ├── settings.py          # Main configuration
│   ├── urls.py              # Root URL configuration
│   ├── asgi.py              # ASGI configuration
│   └── wsgi.py              # WSGI configuration
├── payments/                # Main application
│   ├── models.py            # Data models (H5App, Payment, etc.)
│   ├── views.py             # API views and callback handler
│   ├── serializers.py       # DRF serializers
│   ├── services.py          # Decryption service
│   ├── urls.py              # App URL patterns
│   ├── admin.py             # Django admin configuration
│   └── migrations/          # Database migrations
├── logs/                    # Application logs
├── callback-payload/        # Saved callback payloads (auto-created)
├── db.sqlite3               # SQLite database (dev)
├── requirements.txt         # Python dependencies
├── Pipfile                  # Pipenv dependencies
├── manage.py                # Django management script
└── .env                     # Environment variables (git-ignored)
```

### Dependencies (requirements.txt)
```
Django==4.2.7
djangorestframework==3.14.0
mysqlclient==2.2.0
python-decouple==3.8
cryptography==41.0.7
django-cors-headers==4.3.1
Pillow==10.1.0
drf-yasg==1.21.7
```

### Setup Commands
```bash
# Create virtual environment
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Create .env file from template
cp env.example .env

# Run migrations
python manage.py migrate

# Create superuser
python manage.py createsuperuser

# Start development server
python manage.py runserver
```

---

## Database Architecture

### Models Overview

#### 1. H5App Model
**Purpose**: Store H5 mobile web application configurations

**Fields**:
- `id` (UUID, PK): Unique identifier
- `name` (CharField): Application name
- `description` (TextField): App description
- `app_key` (CharField, unique): Unique identifier for SuperApp integration
- `encryption_key` (TextField): Encryption key for decrypting callbacks
- `notify_url` (URLField): Callback URL for notifications
- `is_active` (BooleanField): Active status flag
- `created_at` (DateTimeField): Creation timestamp
- `updated_at` (DateTimeField): Last update timestamp

**Relationships**:
- One-to-Many with `Payment` model

#### 2. Payment Model
**Purpose**: Store payment transaction records

**Core Fields**:
- `id` (UUID, PK): Unique identifier
- `h5_app` (ForeignKey → H5App): Associated H5 app
- `payment_ref` (CharField, unique): Merchant payment reference
- `amount` (DecimalField): Payment amount
- `currency` (CharField): Currency code (3 chars)
- `status` (CharField): Payment status (pending, processing, completed, failed, cancelled)

**SuperApp Fields** (populated from callbacks):
- `app_id`: SuperApp application ID
- `mch_id`: Merchant ID
- `out_biz_id`: Merchant order number
- `prepay_id`: SuperApp prepay ID
- `payment_order_id`: Payment order ID
- `trade_type`: Transaction type (PAYMENT, REFUND, etc.)
- `superapp_status`: Status from SuperApp (SUCCESS, FAILED, etc.)
- `description`: Payment description
- `finish_time`: Completion timestamp (Unix time)
- `order_amount`: Order amount in cents
- `paid_amount`: Paid amount in cents
- `payment_product`: Payment product type
- `callback_info`: Additional callback information

**Refund Fields** (for refund transactions):
- `original_out_biz_id`: Original merchant order number
- `original_prepay_id`: Original prepay ID
- `original_payment_order_id`: Original payment order ID
- `original_order_amount`: Original order amount in cents
- `original_paid_amount`: Original paid amount in cents

**Raw Data Fields**:
- `ciphertext` (TextField): Encrypted payload from SuperApp
- `decrypted_data` (JSONField): Full decrypted JSON data

**Customer Fields**:
- `customer_email`: Customer email
- `customer_phone`: Customer phone
- `order_id`: External order ID

**Timestamps**:
- `created_at`: Payment creation time
- `updated_at`: Last update time
- `callback_received_at`: When callback was processed

**Indexes**:
- Index on `payment_ref` (unique)
- Compound index on `h5_app` + `status`
- Index on `created_at`

#### 3. PaymentCallbackLog Model
**Purpose**: Audit log for all callback attempts

**Fields**:
- `id` (UUID, PK): Unique identifier
- `payment` (ForeignKey → Payment): Associated payment
- `raw_payload` (JSONField): Original callback payload
- `response_sent` (JSONField): Response sent back to SuperApp
- `http_status` (IntegerField): HTTP status code
- `received_at` (DateTimeField): Callback timestamp
- `error_message` (TextField): Error details if failed
- `is_successful` (BooleanField): Success flag

---

## API Endpoints & Logic

### URL Configuration

**Root URLs** (`h5_backend_api/urls.py`):
```python
urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/', include('payments.urls')),
    path('swagger/', schema_view.with_ui('swagger')),
    path('redoc/', schema_view.with_ui('redoc')),
]
```

**App URLs** (`payments/urls.py`):
```python
urlpatterns = [
    # H5 Apps
    path('h5-apps/', views.H5AppListCreateView.as_view()),
    path('h5-apps/<uuid:id>/', views.H5AppRetrieveUpdateDestroyView.as_view()),
    path('h5-apps/<uuid:id>/payments/', views.H5AppPaymentsView.as_view()),
    
    # Payments
    path('payments/', views.PaymentListCreateView.as_view()),
    path('payments/<uuid:id>/', views.PaymentRetrieveView.as_view()),
    path('payments/stats/', views.PaymentStatsView.as_view()),
    path('payments/callback-logs/', views.PaymentCallbackLogsView.as_view()),
    
    # SuperApp Callback
    path('payment/callback/', views.payment_callback),
]
```

### Endpoint Details

#### 1. H5 Apps Management

**GET /api/h5-apps/** - List all H5 apps
- Query params: `is_active`, `search` (name or app_key)
- Returns: Paginated list with payment counts and totals

**POST /api/h5-apps/** - Create new H5 app
- Request body: `name`, `description`, `app_key`, `encryption_key`, `notify_url`, `is_active`
- Validates: unique app_key, URL format

**GET /api/h5-apps/{id}/** - Get H5 app details
- Returns: Full app details with payment statistics

**PUT/PATCH /api/h5-apps/{id}/** - Update H5 app
- Supports partial updates

**DELETE /api/h5-apps/{id}/** - Delete H5 app
- Cascade deletes associated payments

**GET /api/h5-apps/{id}/payments/** - Get payments for app
- Query params: `status`, `start_date`, `end_date`

#### 2. Payments Management

**GET /api/payments/** - List all payments
- Query params: `h5_app`, `status`, `payment_ref`
- Returns: Paginated list with H5 app details

**POST /api/payments/** - Create new payment
- Request body: `h5_app`, `payment_ref`, `amount`, `currency`, etc.
- Validates: positive amount, valid currency

**GET /api/payments/{id}/** - Get payment details
- Returns: Full payment details with SuperApp fields

**GET /api/payments/stats/** - Payment statistics
- Query params: `h5_app_id` (optional)
- Returns: Total/completed/pending/failed counts and amounts

**GET /api/payments/callback-logs/** - Callback audit logs
- Query params: `payment_id`, `is_successful`
- Returns: Log entries for debugging

#### 3. SuperApp Callback

**POST /api/payment/callback/** - Receive payment notification

This is the core endpoint that processes encrypted callbacks from SuperApp.

**Callback Flow**:
1. Receive encrypted payload
2. Log raw payload to file
3. Extract encryption parameters
4. Find H5App by serialNo (app_key)
5. Decrypt ciphertext using app's encryption key
6. Find or create Payment record
7. Update payment with decrypted data
8. Return success response

**Request Format**:
```json
{
  "serialNo": "app_key_from_h5_app",
  "prepayId": "superapp_prepay_id",
  "algorithm": "AEAD_AES_256_GCM",
  "ciphertext": "base64_encrypted_data",
  "nonce": "base64_nonce",
  "associatedData": "JOYPAY"
}
```

**Response Format**:
```json
{
  "code": "SUCCESS"
}
```

---

## Encryption & Security

### Encryption Service (`services.py`)

The `DecryptionService` class handles multiple encryption algorithms:

#### 1. AES-256-GCM (Default)
**Algorithm**: `AEAD_AES_256_GCM`
**Key Format**: 32 bytes (base64 encoded or raw)
**Nonce Format**: 12 bytes (base64 encoded)
**Associated Data**: UTF-8 string (e.g., "JOYPAY")

**Process**:
1. Decode encryption key (base64 or UTF-8)
2. Validate key is 32 bytes
3. Decode nonce from base64 (12 bytes)
4. Decode ciphertext from base64
5. Encode associated data to UTF-8 bytes
6. Decrypt using AESGCM
7. Parse JSON from decrypted bytes

#### 2. AES-192-GCM
**Algorithm**: `AEAD_AES_192_GCM`
**Key Format**: 24 bytes (UTF-8 string encoded)
**Nonce Format**: UTF-8 string (12 bytes when encoded)
**Associated Data**: UTF-8 string

**Process**:
1. Encode key as UTF-8 bytes (24 bytes)
2. Encode nonce as UTF-8 bytes
3. Decode ciphertext from base64
4. AESGCM automatically handles auth tag
5. Decrypt and parse JSON

#### 3. Fernet (Legacy)
**Algorithm**: Fallback for backward compatibility
**Key Format**: PBKDF2-derived Fernet key
**Process**: Standard Fernet decryption

### Security Considerations
- Encryption keys stored securely in database
- Keys marked as `write_only` in serializers
- SSL/TLS recommended for production
- Sensitive data in environment variables
- Comprehensive logging for audit trail
- Input validation on all endpoints

---

## Callbacks & Payment Processing

### Callback Handler Logic

**Step-by-Step Process** (`payment_callback` function):

1. **Capture Raw Body**
   - Read raw HTTP request body to preserve full ciphertext
   - Log length and preview for verification

2. **Parse Payload**
   - Parse JSON from raw body
   - Extract: `serialNo`, `prepayId`, `algorithm`, `ciphertext`, `nonce`, `associatedData`

3. **Save Payload**
   - Create `callback-payload/` directory
   - Save as JSON: `callback_HHMMSS_DDMMYYYY.json`
   - Include: timestamp, headers, payload, raw_body

4. **Validate Fields**
   - Check required fields present
   - Return 400 if missing

5. **Find H5App**
   - Query by `app_key` matching `serialNo`
   - Check if app is active
   - Return 404 if not found

6. **Decrypt Data**
   - Call `DecryptionService.decrypt_ciphertext()`
   - Handle various algorithms
   - Return 400 if decryption fails

7. **Process Payment**
   - Find existing payment by `payment_ref` (outBizId)
   - Create new payment if not found
   - Update with decrypted fields:
     - SuperApp IDs: appId, mchId, outBizId, prepayId, paymentOrderId
     - Status: tradeType, status
     - Amounts: orderAmount, paidAmount (convert cents to decimal)
     - Metadata: finishTime, description, callbackInfo
     - Refund fields if applicable
   - Update payment status based on SuperApp status
   - Save payment record

8. **Response**
   - Return `{"code": "SUCCESS"}` with 200 status

### Decrypted Data Structure

Example decrypted JSON:
```json
{
  "appId": "superapp_app_id",
  "mchId": "merchant_id",
  "outBizId": "merchant_order_12345",
  "prepayId": "superapp_prepay_id",
  "paymentOrderId": "payment_order_id",
  "tradeType": "PAYMENT",
  "status": "SUCCESS",
  "orderAmount": 10000,
  "paidAmount": 10000,
  "currency": "USD",
  "finishTime": 1699123456789,
  "description": "Product Purchase",
  "callbackInfo": "order_details",
  "paymentProduct": "InAppH5",
  "originalOutBizId": null,
  "originalPrepayId": null,
  ...
}
```

### Payment Status Mapping
- `SUCCESS` → `completed`
- `FAILED`, `FAIL` → `failed`
- `PENDING`, `PROCESSING` → `processing`

---

## Configuration & Deployment

### Settings Configuration (`settings.py`)

**Core Settings**:
```python
INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'rest_framework',
    'corsheaders',
    'drf_yasg',
    'payments',
]

MIDDLEWARE = [
    'corsheaders.middleware.CorsMiddleware',
    # ... other middleware
]
```

**Database Configuration**:
```python
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.mysql',
        'NAME': config('DB_NAME', default='hfive'),
        'USER': config('DB_USER', default='adminuser'),
        'PASSWORD': config('DB_PASSWORD', default='...'),
        'HOST': config('DB_HOST', default='...'),
        'PORT': config('DB_PORT', default='3306'),
        'OPTIONS': {
            'init_command': "SET sql_mode='STRICT_TRANS_TABLES'",
            'charset': 'utf8mb4',
            'ssl': True,  # For Azure MySQL
        },
    }
}
```

**REST Framework**:
```python
REST_FRAMEWORK = {
    'DEFAULT_PAGINATION_CLASS': 'PageNumberPagination',
    'PAGE_SIZE': 20,
    'DEFAULT_FILTER_BACKENDS': [
        'SearchFilter',
        'OrderingFilter',
    ],
}
```

**CORS Configuration**:
```python
CORS_ALLOWED_ORIGINS = config(
    'CORS_ALLOWED_ORIGINS',
    default='http://localhost:3000',
    cast=lambda v: [s.strip() for s in v.split(',')]
)
```

**Logging**:
```python
LOGGING = {
    'handlers': {
        'file': {
            'filename': BASE_DIR / 'logs' / 'django.log',
        },
        'console': {},
    },
    'loggers': {
        'payments': {
            'level': 'DEBUG',
        },
    },
}
```

### Environment Variables (`.env`)

```env
# Database
DB_NAME=hfive
DB_USER=adminuser
DB_PASSWORD=AppUserPass456!
DB_HOST=40.81.17.177
DB_PORT=3306

# Django
SECRET_KEY=your-secret-key-here
DEBUG=True
ALLOWED_HOSTS=localhost,127.0.0.1

# CORS
CORS_ALLOWED_ORIGINS=http://localhost:3000
```

---

## Step-by-Step Implementation Guide

### Phase 1: Project Setup

1. **Create Django Project**
   ```bash
   django-admin startproject h5_backend_api
   cd h5_backend_api
   ```

2. **Create Payments App**
   ```bash
   python manage.py startapp payments
   ```

3. **Install Dependencies**
   - Create `requirements.txt` with all dependencies
   - Run `pip install -r requirements.txt`

4. **Configure Settings**
   - Add apps to `INSTALLED_APPS`
   - Configure database
   - Set up CORS and REST framework

### Phase 2: Database Models

1. **Create H5App Model** (`payments/models.py`)
   - Define fields and relationships
   - Add `__str__` method
   - Configure Meta options

2. **Create Payment Model**
   - Add all fields (core, SuperApp, refund, raw data)
   - Define status choices
   - Add indexes for performance
   - Configure ordering

3. **Create PaymentCallbackLog Model**
   - Fields for auditing
   - ForeignKey to Payment

4. **Run Migrations**
   ```bash
   python manage.py makemigrations
   python manage.py migrate
   ```

### Phase 3: Serializers

1. **Create H5AppSerializer**
   - Include computed fields (payments_count, total_amount)
   - Mark encryption_key as write_only
   - Add validation methods

2. **Create PaymentSerializer**
   - Include h5_app details
   - Mark all SuperApp fields as read-only
   - Add validation

3. **Create Other Serializers**
   - PaymentCallbackSerializer
   - PaymentCallbackLogSerializer
   - PaymentStatsSerializer

### Phase 4: Views & APIs

1. **Create Generic Views**
   - H5AppListCreateView (ListCreateAPIView)
   - H5AppRetrieveUpdateDestroyView
   - H5AppPaymentsView
   - PaymentListCreateView
   - PaymentRetrieveView

2. **Create Statistics View**
   - PaymentStatsView (APIView)
   - Query aggregations

3. **Create Callback Logs View**
   - PaymentCallbackLogsView (ListAPIView)

### Phase 5: Decryption Service

1. **Create DecryptionService Class**
   - `decrypt_ciphertext()` method
   - `_decrypt_aes256_gcm()` method
   - `_decrypt_aes192_gcm()` method
   - `_decrypt_fernet()` method
   - `validate_payment_data()` method

2. **Test Decryption**
   - Create test scripts
   - Verify against known data

### Phase 6: Callback Handler

1. **Create Callback Endpoint**
   - `payment_callback()` function
   - Handle raw body capture
   - Save payloads to files
   - Implement decryption flow
   - Update payment records

2. **Error Handling**
   - Comprehensive logging
   - Graceful error responses
   - Status code handling

### Phase 7: URL Configuration

1. **Configure Root URLs**
   - Add payments.urls
   - Add Swagger/ReDoc paths

2. **Configure App URLs**
   - Map views to paths
   - Use UUID lookup fields

### Phase 8: Admin Interface

1. **Register Models**
   - Configure list_display
   - Add list_filter
   - Set search_fields
   - Define readonly_fields
   - Create fieldsets

2. **Test Admin**
   ```bash
   python manage.py createsuperuser
   python manage.py runserver
   ```

### Phase 9: Testing & Documentation

1. **API Testing**
   - Use Swagger UI at `/swagger/`
   - Test all endpoints
   - Verify callbacks

2. **Documentation**
   - Update README.md
   - Add endpoint examples
   - Document callbacks

### Phase 10: Deployment

1. **Production Settings**
   - Set DEBUG=False
   - Configure ALLOWED_HOSTS
   - Use production database
   - Enable SSL

2. **Security Hardening**
   - Rotate SECRET_KEY
   - Secure database credentials
   - Enable HTTPS
   - Configure firewall

3. **Monitoring**
   - Set up logging
   - Monitor callback failures
   - Track payment stats

---

## Key Implementation Details

### UUID vs Integer IDs
- All models use UUID primary keys for security
- URLs use `<uuid:id>` pattern
- Lookup field is `'id'`

### Amount Handling
- SuperApp sends amounts in smallest currency unit (cents)
- Storage uses `BigIntegerField` for original cents
- Display converts to `DecimalField` for user-friendly amounts
- Helper functions: `safe_int()`, `safe_amount_from_cents()`

### Callback Payload Saving
- Automatic file saving for debugging
- Format: `callback_HHMMSS_DDMMYYYY.json`
- Includes: headers, payload, raw_body, decrypted_data
- Directory auto-created if missing

### Query Optimization
- `select_related()` for foreign keys
- Database indexes on common queries
- Pagination for large datasets

### Error Handling
- Try-except blocks around all risky operations
- Detailed logging with logger
- Graceful degradation
- Proper HTTP status codes

---

## Testing the System

### Create H5 App
```bash
POST /api/h5-apps/
{
  "name": "Test App",
  "app_key": "test_app_123",
  "encryption_key": "your_32_byte_key_here",
  "notify_url": "https://your-callback-url.com/callback",
  "is_active": true
}
```

### Test Callback
```bash
POST /api/payment/callback/
{
  "serialNo": "test_app_123",
  "prepayId": "test_prepay_123",
  "algorithm": "AEAD_AES_256_GCM",
  "ciphertext": "encrypted_data_here",
  "nonce": "base64_nonce_here",
  "associatedData": "JOYPAY"
}
```

### Query Payments
```bash
GET /api/payments/?status=completed
GET /api/h5-apps/{id}/payments/
GET /api/payments/stats/
```

---

## Common Issues & Solutions

### Issue: Decryption Fails
- Check encryption key format (32 bytes for AES-256)
- Verify nonce encoding (base64 vs UTF-8)
- Ensure algorithm matches encryption method
- Check ciphertext is complete

### Issue: Payment Not Found
- Verify app_key matches serialNo
- Check H5App is active
- Ensure payment_ref exists in database

### Issue: Callback Payload Truncated
- Use raw body capture (implemented)
- Check Content-Length header
- Verify JSON parsing doesn't truncate

### Issue: Database Connection
- Verify MySQL credentials
- Check network connectivity
- Ensure SSL is properly configured
- Test with MySQL client

---

## Future Enhancements

1. **Authentication**
   - JWT token authentication
   - API key authentication
   - Role-based permissions

2. **Webhooks**
   - Notify external systems on payment updates
   - Configurable webhook endpoints
   - Retry mechanism

3. **Analytics**
   - Dashboard with charts
   - Export reports
   - Payment trends

4. **Testing**
   - Unit tests for models
   - Integration tests for APIs
   - Mock SuperApp callbacks

5. **Performance**
   - Caching layer (Redis)
   - Async task processing (Celery)
   - Database query optimization

---

## Conclusion

This architecture provides a robust, scalable foundation for processing encrypted payment callbacks from SuperApp. The modular design allows for easy extension and maintenance. The comprehensive logging and audit trail ensure transparency and debuggability.

For questions or issues, refer to the code comments, Django documentation, and SuperApp integration guides.



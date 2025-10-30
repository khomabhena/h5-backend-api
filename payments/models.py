from django.db import models
from django.utils import timezone
import uuid


class H5App(models.Model):
    """
    Model to store H5 app information
    Each H5 app can have multiple payments associated with it
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=255, help_text="Name of the H5 app")
    description = models.TextField(blank=True, null=True, help_text="Description of the H5 app")
    app_key = models.CharField(max_length=255, unique=True, help_text="Unique key for the H5 app")
    
    # SuperApp integration settings
    encryption_key = models.TextField(help_text="Encryption key for SuperApp integration")
    notify_url = models.URLField(help_text="Callback URL for payment notifications")
    
    # App configuration
    is_active = models.BooleanField(default=True, help_text="Whether the app is active")
    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'h5_apps'
        verbose_name = 'H5 App'
        verbose_name_plural = 'H5 Apps'
        ordering = ['-created_at']
    
    def __str__(self):
        return f"{self.name} ({self.app_key})"


class Payment(models.Model):
    """
    Model to store payment information
    Each payment is associated with an H5 app
    """
    PAYMENT_STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('processing', 'Processing'),
        ('completed', 'Completed'),
        ('failed', 'Failed'),
        ('cancelled', 'Cancelled'),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    h5_app = models.ForeignKey(H5App, on_delete=models.CASCADE, related_name='payments')
    
    # Payment details
    payment_ref = models.CharField(max_length=255, unique=True, help_text="Unique payment reference")
    amount = models.DecimalField(max_digits=10, decimal_places=2, help_text="Payment amount")
    currency = models.CharField(max_length=3, default='USD', help_text="Currency code")
    status = models.CharField(max_length=20, choices=PAYMENT_STATUS_CHOICES, default='pending')
    
    # SuperApp callback data
    ciphertext = models.TextField(blank=True, null=True, help_text="Encrypted payment data from SuperApp")
    decrypted_data = models.JSONField(blank=True, null=True, help_text="Decrypted payment data")
    
    # Timestamps
    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(auto_now=True)
    callback_received_at = models.DateTimeField(blank=True, null=True, help_text="When callback was received")
    
    # Additional metadata
    customer_email = models.EmailField(blank=True, null=True)
    customer_phone = models.CharField(max_length=20, blank=True, null=True)
    order_id = models.CharField(max_length=255, blank=True, null=True, help_text="External order ID")
    
    class Meta:
        db_table = 'payments'
        verbose_name = 'Payment'
        verbose_name_plural = 'Payments'
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['payment_ref']),
            models.Index(fields=['h5_app', 'status']),
            models.Index(fields=['created_at']),
        ]
    
    def __str__(self):
        return f"Payment {self.payment_ref} - {self.amount} {self.currency}"


class PaymentCallbackLog(models.Model):
    """
    Model to log all payment callback attempts for debugging and auditing
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    payment = models.ForeignKey(Payment, on_delete=models.CASCADE, related_name='callback_logs')
    
    # Callback details
    raw_payload = models.JSONField(help_text="Raw callback payload received")
    response_sent = models.JSONField(help_text="Response sent back to SuperApp")
    http_status = models.IntegerField(help_text="HTTP status code returned")
    
    # Timestamps
    received_at = models.DateTimeField(default=timezone.now)
    
    # Error tracking
    error_message = models.TextField(blank=True, null=True)
    is_successful = models.BooleanField(default=False)
    
    class Meta:
        db_table = 'payment_callback_logs'
        verbose_name = 'Payment Callback Log'
        verbose_name_plural = 'Payment Callback Logs'
        ordering = ['-received_at']
    
    def __str__(self):
        return f"Callback Log for {self.payment.payment_ref} - {self.received_at}"
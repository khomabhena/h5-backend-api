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
    
    # SuperApp decrypted fields (from callback)
    app_id = models.CharField(max_length=255, blank=True, null=True, help_text="SuperApp App ID")
    mch_id = models.CharField(max_length=255, blank=True, null=True, help_text="Merchant ID from SuperApp")
    out_biz_id = models.CharField(max_length=255, blank=True, null=True, help_text="Merchant order number (outBizId)")
    prepay_id = models.CharField(max_length=255, blank=True, null=True, help_text="Prepay ID from SuperApp")
    payment_order_id = models.CharField(max_length=255, blank=True, null=True, help_text="Payment Order ID from SuperApp")
    trade_type = models.CharField(max_length=50, blank=True, null=True, help_text="Trade type (PAYMENT, REFUND, etc.)")
    superapp_status = models.CharField(max_length=50, blank=True, null=True, help_text="Status from SuperApp (SUCCESS, FAILED, etc.)")
    description = models.TextField(blank=True, null=True, help_text="Payment description from SuperApp")
    finish_time = models.BigIntegerField(blank=True, null=True, help_text="Finish time timestamp from SuperApp")
    order_amount = models.BigIntegerField(blank=True, null=True, help_text="Order amount in smallest currency unit (cents)")
    paid_amount = models.BigIntegerField(blank=True, null=True, help_text="Paid amount in smallest currency unit (cents)")
    payment_product = models.CharField(max_length=100, blank=True, null=True, help_text="Payment product (e.g., InAppH5)")
    callback_info = models.TextField(blank=True, null=True, help_text="Callback info from SuperApp")
    
    # Original payment fields (for refunds)
    original_out_biz_id = models.CharField(max_length=255, blank=True, null=True, help_text="Original merchant order number (for refunds)")
    original_prepay_id = models.CharField(max_length=255, blank=True, null=True, help_text="Original prepay ID (for refunds)")
    original_payment_order_id = models.CharField(max_length=255, blank=True, null=True, help_text="Original payment order ID (for refunds)")
    original_order_amount = models.BigIntegerField(blank=True, null=True, help_text="Original order amount in cents (for refunds)")
    original_paid_amount = models.BigIntegerField(blank=True, null=True, help_text="Original paid amount in cents (for refunds)")
    
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
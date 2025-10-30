from rest_framework import serializers
from .models import H5App, Payment, PaymentCallbackLog


class H5AppSerializer(serializers.ModelSerializer):
    """
    Serializer for H5App model with full CRUD operations
    """
    payments_count = serializers.SerializerMethodField()
    total_payments_amount = serializers.SerializerMethodField()
    
    class Meta:
        model = H5App
        fields = [
            'id', 'name', 'description', 'app_key', 'encryption_key',
            'notify_url', 'is_active', 'created_at', 'updated_at',
            'payments_count', 'total_payments_amount'
        ]
        read_only_fields = ['id', 'created_at', 'updated_at']
        extra_kwargs = {
            'encryption_key': {'write_only': True},  # Don't expose encryption key in responses
        }
    
    def get_payments_count(self, obj):
        """Get the total number of payments for this H5 app"""
        return obj.payments.count()
    
    def get_total_payments_amount(self, obj):
        """Get the total amount of completed payments for this H5 app"""
        from django.db.models import Sum
        total = obj.payments.filter(status='completed').aggregate(
            total=Sum('amount')
        )['total']
        return total or 0
    
    def validate_app_key(self, value):
        """Ensure app_key is unique"""
        if H5App.objects.filter(app_key=value).exclude(id=self.instance.id if self.instance else None).exists():
            raise serializers.ValidationError("An H5 app with this key already exists.")
        return value
    
    def validate_notify_url(self, value):
        """Basic URL validation"""
        if not value.startswith(('http://', 'https://')):
            raise serializers.ValidationError("Notify URL must start with http:// or https://")
        return value


class H5AppCreateSerializer(serializers.ModelSerializer):
    """
    Simplified serializer for creating H5 apps
    """
    class Meta:
        model = H5App
        fields = ['name', 'description', 'app_key', 'encryption_key', 'notify_url', 'is_active']
        extra_kwargs = {
            'encryption_key': {'write_only': True},
        }
    
    def validate_app_key(self, value):
        """Ensure app_key is unique"""
        if H5App.objects.filter(app_key=value).exists():
            raise serializers.ValidationError("An H5 app with this key already exists.")
        return value


class PaymentSerializer(serializers.ModelSerializer):
    """
    Serializer for Payment model
    """
    h5_app_name = serializers.CharField(source='h5_app.name', read_only=True)
    h5_app_key = serializers.CharField(source='h5_app.app_key', read_only=True)
    
    class Meta:
        model = Payment
        fields = [
            'id', 'h5_app', 'h5_app_name', 'h5_app_key', 'payment_ref',
            'amount', 'currency', 'status', 'customer_email', 'customer_phone',
            'order_id', 'created_at', 'updated_at', 'callback_received_at'
        ]
        read_only_fields = [
            'id', 'h5_app_name', 'h5_app_key', 'created_at', 'updated_at',
            'callback_received_at'
        ]
    
    def validate_amount(self, value):
        """Ensure amount is positive"""
        if value <= 0:
            raise serializers.ValidationError("Amount must be greater than zero.")
        return value


class PaymentCallbackSerializer(serializers.Serializer):
    """
    Serializer for handling SuperApp payment callbacks
    """
    ciphertext = serializers.CharField(required=True)
    payment_ref = serializers.CharField(required=True)
    timestamp = serializers.IntegerField(required=False)
    
    def validate_payment_ref(self, value):
        """Validate that payment reference exists"""
        try:
            Payment.objects.get(payment_ref=value)
        except Payment.DoesNotExist:
            raise serializers.ValidationError("Payment reference not found.")
        return value


class PaymentCallbackLogSerializer(serializers.ModelSerializer):
    """
    Serializer for PaymentCallbackLog model (read-only for debugging)
    """
    payment_ref = serializers.CharField(source='payment.payment_ref', read_only=True)
    
    class Meta:
        model = PaymentCallbackLog
        fields = [
            'id', 'payment', 'payment_ref', 'raw_payload', 'response_sent',
            'http_status', 'received_at', 'error_message', 'is_successful'
        ]
        read_only_fields = '__all__'


class PaymentStatsSerializer(serializers.Serializer):
    """
    Serializer for payment statistics
    """
    total_payments = serializers.IntegerField()
    completed_payments = serializers.IntegerField()
    pending_payments = serializers.IntegerField()
    failed_payments = serializers.IntegerField()
    total_amount = serializers.DecimalField(max_digits=10, decimal_places=2)
    completed_amount = serializers.DecimalField(max_digits=10, decimal_places=2)


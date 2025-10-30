from django.contrib import admin
from .models import H5App, Payment, PaymentCallbackLog


@admin.register(H5App)
class H5AppAdmin(admin.ModelAdmin):
    list_display = ['name', 'app_key', 'is_active', 'created_at']
    list_filter = ['is_active', 'created_at']
    search_fields = ['name', 'app_key', 'description']
    readonly_fields = ['id', 'created_at', 'updated_at']
    fieldsets = (
        ('Basic Information', {
            'fields': ('name', 'description', 'app_key')
        }),
        ('Configuration', {
            'fields': ('encryption_key', 'notify_url', 'is_active')
        }),
        ('Timestamps', {
            'fields': ('id', 'created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )


@admin.register(Payment)
class PaymentAdmin(admin.ModelAdmin):
    list_display = ['payment_ref', 'h5_app', 'amount', 'currency', 'status', 'created_at']
    list_filter = ['status', 'currency', 'h5_app', 'created_at']
    search_fields = ['payment_ref', 'customer_email', 'order_id']
    readonly_fields = ['id', 'created_at', 'updated_at', 'callback_received_at']
    fieldsets = (
        ('Payment Information', {
            'fields': ('payment_ref', 'h5_app', 'amount', 'currency', 'status')
        }),
        ('Customer Information', {
            'fields': ('customer_email', 'customer_phone', 'order_id')
        }),
        ('Callback Data', {
            'fields': ('ciphertext', 'decrypted_data', 'callback_received_at'),
            'classes': ('collapse',)
        }),
        ('Timestamps', {
            'fields': ('id', 'created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )


@admin.register(PaymentCallbackLog)
class PaymentCallbackLogAdmin(admin.ModelAdmin):
    list_display = ['payment', 'is_successful', 'http_status', 'received_at']
    list_filter = ['is_successful', 'http_status', 'received_at']
    search_fields = ['payment__payment_ref', 'error_message']
    readonly_fields = ['id', 'received_at']
    fieldsets = (
        ('Callback Information', {
            'fields': ('payment', 'is_successful', 'http_status', 'received_at')
        }),
        ('Payload Data', {
            'fields': ('raw_payload', 'response_sent'),
            'classes': ('collapse',)
        }),
        ('Error Information', {
            'fields': ('error_message',),
            'classes': ('collapse',)
        }),
    )
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
    list_display = ['payment_ref', 'h5_app', 'amount', 'currency', 'status', 'superapp_status', 'created_at']
    list_filter = ['status', 'superapp_status', 'trade_type', 'currency', 'h5_app', 'created_at']
    search_fields = ['payment_ref', 'prepay_id', 'payment_order_id', 'out_biz_id', 'customer_email', 'order_id', 'app_id', 'mch_id']
    readonly_fields = [
        'id', 'created_at', 'updated_at', 'callback_received_at',
        # SuperApp fields are read-only (from callbacks)
        'app_id', 'mch_id', 'out_biz_id', 'prepay_id', 'payment_order_id',
        'trade_type', 'superapp_status', 'description', 'finish_time',
        'order_amount', 'paid_amount', 'payment_product', 'callback_info',
        'original_out_biz_id', 'original_prepay_id', 'original_payment_order_id',
        'original_order_amount', 'original_paid_amount', 'decrypted_data'
    ]
    fieldsets = (
        ('Payment Information', {
            'fields': ('payment_ref', 'h5_app', 'amount', 'currency', 'status')
        }),
        ('SuperApp Details', {
            'fields': (
                'app_id', 'mch_id', 'prepay_id', 'payment_order_id', 'out_biz_id',
                'trade_type', 'superapp_status', 'payment_product', 'description'
            )
        }),
        ('SuperApp Amounts', {
            'fields': ('order_amount', 'paid_amount', 'finish_time'),
            'classes': ('collapse',)
        }),
        ('Original Payment (Refunds)', {
            'fields': (
                'original_out_biz_id', 'original_prepay_id', 'original_payment_order_id',
                'original_order_amount', 'original_paid_amount'
            ),
            'classes': ('collapse',)
        }),
        ('Customer Information', {
            'fields': ('customer_email', 'customer_phone', 'order_id', 'callback_info')
        }),
        ('Raw Callback Data', {
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
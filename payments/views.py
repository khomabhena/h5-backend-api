from rest_framework import generics, status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView
from django.shortcuts import get_object_or_404
from django.db.models import Q, Sum, Count
from django.utils import timezone
import logging
import json
import os
import traceback
from pathlib import Path
from datetime import datetime

from .models import H5App, Payment, PaymentCallbackLog
from .serializers import (
    H5AppSerializer, H5AppCreateSerializer, PaymentSerializer,
    PaymentCallbackSerializer, PaymentCallbackLogSerializer, PaymentStatsSerializer
)
from .services import DecryptionService

logger = logging.getLogger('payments')
db_error_logger = logging.getLogger('db_errors')


class H5AppListCreateView(generics.ListCreateAPIView):
    """
    List all H5 apps or create a new one
    GET /api/h5-apps/ - List all H5 apps
    POST /api/h5-apps/ - Create a new H5 app
    """
    queryset = H5App.objects.all()
    permission_classes = [AllowAny]  # Adjust permissions as needed
    
    def get_serializer_class(self):
        if self.request.method == 'POST':
            return H5AppCreateSerializer
        return H5AppSerializer
    
    def get_queryset(self):
        queryset = H5App.objects.all()
        
        # Filter by active status
        is_active = self.request.query_params.get('is_active')
        if is_active is not None:
            queryset = queryset.filter(is_active=is_active.lower() == 'true')
        
        # Search by name or app_key
        search = self.request.query_params.get('search')
        if search:
            queryset = queryset.filter(
                Q(name__icontains=search) | Q(app_key__icontains=search)
            )
        
        return queryset.order_by('-created_at')


class H5AppRetrieveUpdateDestroyView(generics.RetrieveUpdateDestroyAPIView):
    """
    Retrieve, update or delete a specific H5 app
    GET /api/h5-apps/{id}/ - Get H5 app details
    PUT /api/h5-apps/{id}/ - Update H5 app
    PATCH /api/h5-apps/{id}/ - Partial update H5 app
    DELETE /api/h5-apps/{id}/ - Delete H5 app
    """
    queryset = H5App.objects.all()
    serializer_class = H5AppSerializer
    permission_classes = [AllowAny]  # Adjust permissions as needed
    lookup_field = 'id'


class H5AppPaymentsView(generics.ListAPIView):
    """
    Get all payments for a specific H5 app
    GET /api/h5-apps/{id}/payments/ - List payments for H5 app
    """
    serializer_class = PaymentSerializer
    permission_classes = [AllowAny]  # Adjust permissions as needed
    
    def get_queryset(self):
        h5_app_id = self.kwargs['id']
        h5_app = get_object_or_404(H5App, id=h5_app_id)
        
        queryset = Payment.objects.filter(h5_app=h5_app)
        
        # Filter by status
        status_filter = self.request.query_params.get('status')
        if status_filter:
            queryset = queryset.filter(status=status_filter)
        
        # Filter by date range
        start_date = self.request.query_params.get('start_date')
        end_date = self.request.query_params.get('end_date')
        
        if start_date:
            queryset = queryset.filter(created_at__gte=start_date)
        if end_date:
            queryset = queryset.filter(created_at__lte=end_date)
        
        return queryset.order_by('-created_at')


class PaymentListCreateView(generics.ListCreateAPIView):
    """
    List all payments or create a new one
    GET /api/payments/ - List all payments
    POST /api/payments/ - Create a new payment
    """
    queryset = Payment.objects.select_related('h5_app').all()
    serializer_class = PaymentSerializer
    permission_classes = [AllowAny]  # Adjust permissions as needed
    
    def get_queryset(self):
        queryset = Payment.objects.select_related('h5_app').all()
        
        # Filter by H5 app
        h5_app_id = self.request.query_params.get('h5_app')
        if h5_app_id:
            queryset = queryset.filter(h5_app_id=h5_app_id)
        
        # Filter by status
        status_filter = self.request.query_params.get('status')
        if status_filter:
            queryset = queryset.filter(status=status_filter)
        
        # Filter by payment reference
        payment_ref = self.request.query_params.get('payment_ref')
        if payment_ref:
            queryset = queryset.filter(payment_ref__icontains=payment_ref)
        
        return queryset.order_by('-created_at')


class PaymentRetrieveView(generics.RetrieveAPIView):
    """
    Retrieve a specific payment
    GET /api/payments/{id}/ - Get payment details
    """
    queryset = Payment.objects.select_related('h5_app').all()
    serializer_class = PaymentSerializer
    permission_classes = [AllowAny]  # Adjust permissions as needed
    lookup_field = 'id'


@api_view(['POST'])
@permission_classes([AllowAny])
def payment_callback(request):
    """
    Handle SuperApp payment callback
    POST /api/payment/callback/ - Receive payment notification from SuperApp
    """
    # Capture raw request body first to ensure nothing is lost
    # DRF wraps the request, so we need to access the underlying Django request
    raw_body = None
    try:
        # Access the underlying Django HttpRequest
        django_request = request._request if hasattr(request, '_request') else request
        if hasattr(django_request, 'body'):
            body_bytes = django_request.body
            # Ensure we read the full body (might be a stream)
            if hasattr(body_bytes, 'read'):
                body_bytes = body_bytes.read()
            if isinstance(body_bytes, bytes):
                raw_body = body_bytes.decode('utf-8')
            else:
                raw_body = body_bytes
            logger.info(f"Raw body captured: {len(raw_body)} characters")
    except Exception as e:
        logger.warning(f"Could not capture raw body: {str(e)}")
        import traceback
        logger.warning(traceback.format_exc())
    
    # Parse JSON from raw body to ensure full ciphertext is captured
    # DRF's request.data might truncate very long strings
    payload_data = {}
    if raw_body:
        try:
            import json
            payload_data = json.loads(raw_body)
            logger.info(f"Parsed payload from raw_body: {len(raw_body)} chars")
        except Exception as e:
            logger.warning(f"Failed to parse raw_body as JSON: {str(e)}, falling back to request.data")
            # Fallback to request.data if raw_body parsing fails
            if hasattr(request.data, 'dict'):
                payload_data = request.data.dict()
            else:
                payload_data = dict(request.data)
    else:
        # Fallback to request.data if raw_body not available
        if hasattr(request.data, 'dict'):
            payload_data = request.data.dict()
        else:
            payload_data = dict(request.data)
    
    # Ensure ciphertext is fully captured (may be very long)
    ciphertext_full = payload_data.get('ciphertext', '')
    if ciphertext_full:
        logger.info(f"Ciphertext length in payload: {len(ciphertext_full)} characters")
        # Log first and last 50 chars to verify it's complete
        if len(ciphertext_full) > 100:
            logger.info(f"Ciphertext preview: {ciphertext_full[:50]}...{ciphertext_full[-50:]}")
            logger.info(f"Ciphertext ends with: ...{ciphertext_full[-10:]}")
        else:
            logger.info(f"Ciphertext: {ciphertext_full}")
    else:
        logger.warning("Ciphertext not found in payload_data!")
        
    # Double-check: if raw_body exists, verify ciphertext length matches
    if raw_body and 'ciphertext' in raw_body:
        # Extract ciphertext from raw_body to compare lengths
        try:
            raw_payload_check = json.loads(raw_body)
            raw_ciphertext = raw_payload_check.get('ciphertext', '')
            if raw_ciphertext and len(raw_ciphertext) != len(ciphertext_full):
                logger.warning(f"CIPHERTEXT LENGTH MISMATCH! Parsed: {len(ciphertext_full)}, Raw: {len(raw_ciphertext)}")
                logger.warning("Using ciphertext from raw_body instead")
                payload_data['ciphertext'] = raw_ciphertext
                ciphertext_full = raw_ciphertext
        except:
            pass
    
    # Extract headers from request
    headers = {}
    # Get the underlying Django HttpRequest
    django_request = request._request if hasattr(request, '_request') else request
    
    # Method 1: Try Django request.headers (available in Django 2.2+)
    if hasattr(django_request, 'headers'):
        for key, value in django_request.headers.items():
            headers[key] = value
    
    # Method 2: Extract from request.META (for DRF and older Django)
    # DRF request.META contains HTTP_ prefixed headers
    if hasattr(request, 'META'):
        meta = request.META
    elif hasattr(django_request, 'META'):
        meta = django_request.META
    else:
        meta = {}
    
    for key, value in meta.items():
        if key.startswith('HTTP_'):
            # Convert HTTP_HEADER_NAME to Header-Name format
            # HTTP_AUTHORIZATION -> Authorization
            header_name = key[5:].replace('_', '-').title()
            # Preserve original if we haven't added it via request.headers
            if header_name not in headers:
                headers[header_name] = value
        elif key in ['CONTENT_TYPE', 'CONTENT_LENGTH']:
            # Content-Type and Content-Length are special
            header_name = key.replace('_', '-').title()
            if header_name not in headers:
                headers[header_name] = value
    
    # Ensure we capture Content-Type if available
    if not headers.get('Content-Type') and meta.get('CONTENT_TYPE'):
        headers['Content-Type'] = meta.get('CONTENT_TYPE')
    
    # Log the payload and headers to console (ciphertext may be truncated in logs but saved fully)
    logger.info(f"Callback headers: {headers}")
    logger.info(f"Callback payload keys: {list(payload_data.keys())}")
    if 'ciphertext' in payload_data:
        logger.info(f"Ciphertext present in payload: {len(payload_data.get('ciphertext', ''))} chars")
    
    # Initialize variables for file saving
    filepath = None
    saved_data = {
        "timestamp": datetime.now().isoformat(),
        "received_at": timezone.now().isoformat(),
        "headers": headers,
        "payload": payload_data,
        "raw_body": raw_body  # Include raw body as backup
    }
    
    # Save payload to JSON file in callback-payload folder
    try:
        from django.conf import settings
        callback_dir = Path(settings.BASE_DIR) / 'callback-payload'
        callback_dir.mkdir(exist_ok=True)
        
        # Format: callback_HHMMSS_DDMMYYYY.json (time first, date with DDMMYYYY format)
        timestamp = datetime.now().strftime('%H%M%S_%d%m%Y')
        filename = f"callback_{timestamp}.json"
        filepath = callback_dir / filename
        
        # Save with ensure_ascii=False to preserve all characters, no size limits
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(saved_data, f, indent=2, ensure_ascii=False, separators=(',', ': '))
        
        # Verify the saved file contains full ciphertext
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                saved_check = json.load(f)
                saved_ciphertext = saved_check.get('payload', {}).get('ciphertext', '')
                if saved_ciphertext and len(saved_ciphertext) != len(ciphertext_full):
                    logger.error(f"WARNING: Saved ciphertext length ({len(saved_ciphertext)}) differs from captured ({len(ciphertext_full)})")
                else:
                    logger.info(f"Verified: Saved ciphertext length matches ({len(saved_ciphertext)} chars)")
        except Exception as e:
            logger.warning(f"Could not verify saved file: {str(e)}")
        
        logger.info(f"Callback payload saved to: {filepath}")
    except Exception as e:
        logger.error(f"Error saving callback payload to file: {str(e)}")
    
    # Extract callback parameters
    serial_no = payload_data.get('serialNo')
    prepay_id = payload_data.get('prepayId')
    algorithm = payload_data.get('algorithm', 'AEAD_AES_256_GCM')
    ciphertext = payload_data.get('ciphertext')
    nonce = payload_data.get('nonce')
    associated_data = payload_data.get('associatedData', 'JOYPAY')
    
    # If missing critical fields, just save and return success
    if not ciphertext or not nonce:
        logger.warning(f"Missing ciphertext or nonce - saving payload without decryption")
        # Save payload to file only, return success
        return Response({"code": "SUCCESS"}, status=status.HTTP_200_OK)
    
    # Get or create H5App - don't fail if not found, just create with dummy key
    h5_app = None
    if serial_no:
        try:
            h5_app = H5App.objects.get(app_key=serial_no)
        except H5App.DoesNotExist:
            # Create a default H5App if not found - this allows us to save data
            logger.warning(f"H5App not found for serialNo: {serial_no}, creating default app")
            h5_app = H5App.objects.create(
                name=f"Auto-created app for {serial_no}",
                app_key=serial_no,
                encryption_key="default-dummy-key-for-data-storage",  # Won't work for decryption but allows storage
                notify_url="",
                is_active=True
            )
    else:
        # If no serial_no, create a generic default app
        try:
            h5_app = H5App.objects.get(app_key="__default__")
        except H5App.DoesNotExist:
            h5_app = H5App.objects.create(
                name="Default Payment App",
                app_key="__default__",
                encryption_key="default-dummy-key-for-data-storage",
                notify_url="",
                is_active=True
            )
        
    # Try to decrypt the ciphertext, but don't fail if it doesn't work
    decrypted_data = None
    try:
        decrypted_data = DecryptionService.decrypt_ciphertext(
            ciphertext=ciphertext,
            encryption_key=h5_app.encryption_key,
            algorithm=algorithm,
            nonce=nonce,
            associated_data=associated_data
        )
        logger.info(f"Successfully decrypted data for prepayId: {prepay_id}")
        
        # Save decrypted data to the callback file as well
        if filepath:
            try:
                saved_data['decrypted_data'] = decrypted_data
                with open(filepath, 'w', encoding='utf-8') as f:
                    json.dump(saved_data, f, indent=2, ensure_ascii=False)
            except Exception as e:
                logger.warning(f"Could not update callback file with decrypted data: {str(e)}")
            
    except Exception as e:
        logger.warning(f"Failed to decrypt ciphertext: {str(e)} - continuing without decryption")
        # Don't fail, just continue with None decrypted_data
        decrypted_data = None
    
    # Helper function to safely convert to integer (for BigIntegerField)
    def safe_int(value, default=None):
        """Safely convert value to int, return default if conversion fails"""
        if value is None:
            return default
        try:
            return int(value)
        except (ValueError, TypeError):
            logger.warning(f"Could not convert {value} to int, using default {default}")
            return default
    
    # Helper function to safely convert amount from cents to decimal
    def safe_amount_from_cents(value, default=0.0):
        """Safely convert cents to decimal amount"""
        if value is None:
            return default
        try:
            return float(value) / 100
        except (ValueError, TypeError):
            logger.warning(f"Could not convert {value} to amount, using default {default}")
            return default
    
    # Process the decrypted payment data
    # Map decrypted fields: outBizId -> payment_ref, prepayId -> prepayId, etc.
    # Handle case where decryption failed or data is None
    if decrypted_data:
        out_biz_id = decrypted_data.get('outBizId')  # Merchant order number (our payment_ref)
        decrypted_prepay_id = decrypted_data.get('prepayId')
        trade_status = decrypted_data.get('status')  # Should be "SUCCESS"
        order_amount = decrypted_data.get('orderAmount')  # In smallest currency unit (cents)
        paid_amount = decrypted_data.get('paidAmount')
        currency_code = decrypted_data.get('currency', 'USD')
        finish_time = decrypted_data.get('finishTime')
    else:
        # No decrypted data available
        out_biz_id = None
        decrypted_prepay_id = None
        trade_status = None
        order_amount = None
        paid_amount = None
        currency_code = 'USD'
        finish_time = None
    
    # Find or create payment record
    payment_ref = out_biz_id or prepay_id or decrypted_prepay_id or serial_no or "unknown"
    
    # Always save data even without payment_ref - use timestamp as fallback
    if not payment_ref or payment_ref == "unknown":
        payment_ref = f"callback_{int(timezone.now().timestamp())}"
        logger.warning(f"No payment reference found, using generated: {payment_ref}")
    
    try:
        # Try to find existing payment by payment_ref
        try:
            payment = Payment.objects.get(payment_ref=payment_ref, h5_app=h5_app)
        except Payment.DoesNotExist:
            # Create new payment if not found
            # Convert amount from smallest unit (cents) to decimal, with safe defaults
            amount = safe_amount_from_cents(order_amount or paid_amount, default=0.0)
            
            payment = Payment.objects.create(
                h5_app=h5_app,
                payment_ref=payment_ref,
                amount=amount,
                currency=currency_code or 'USD',
                status='pending'
            )
            logger.info(f"Created new payment record: {payment_ref}")
        
        # Update payment with decrypted data
        # The decrypted_data contains all fields from SuperApp:
        # appId, mchId, outBizId, prepayId, paymentOrderId, tradeType, status,
        # callbackInfo, finishTime, orderAmount, paidAmount, currency,
        # originalOutBizId, originalPrepayId, originalPaymentOrderId,
        # originalOrderAmount, originalPaidAmount, paymentProduct, description
        payment.ciphertext = ciphertext
        payment.decrypted_data = decrypted_data  # Full decrypted JSON stored here
        payment.callback_received_at = timezone.now()
        
        # Store all SuperApp decrypted fields with safe handling (only if decrypted_data exists)
        if decrypted_data:
            try:
                if 'appId' in decrypted_data and decrypted_data.get('appId'):
                    payment.app_id = str(decrypted_data.get('appId'))
            except Exception as e:
                logger.warning(f"Error setting app_id: {str(e)}")
            
            try:
                if 'mchId' in decrypted_data and decrypted_data.get('mchId'):
                    payment.mch_id = str(decrypted_data.get('mchId'))
            except Exception as e:
                logger.warning(f"Error setting mch_id: {str(e)}")
            
            try:
                if 'outBizId' in decrypted_data and decrypted_data.get('outBizId'):
                    payment.out_biz_id = str(decrypted_data.get('outBizId'))
            except Exception as e:
                logger.warning(f"Error setting out_biz_id: {str(e)}")
            
            try:
                if 'prepayId' in decrypted_data and decrypted_data.get('prepayId'):
                    payment.prepay_id = str(decrypted_data.get('prepayId'))
            except Exception as e:
                logger.warning(f"Error setting prepay_id: {str(e)}")
            
            try:
                if 'paymentOrderId' in decrypted_data and decrypted_data.get('paymentOrderId'):
                    payment.payment_order_id = str(decrypted_data.get('paymentOrderId'))
            except Exception as e:
                logger.warning(f"Error setting payment_order_id: {str(e)}")
            
            try:
                if 'tradeType' in decrypted_data and decrypted_data.get('tradeType'):
                    payment.trade_type = str(decrypted_data.get('tradeType'))
            except Exception as e:
                logger.warning(f"Error setting trade_type: {str(e)}")
            
            try:
                if 'status' in decrypted_data and decrypted_data.get('status'):
                    payment.superapp_status = str(decrypted_data.get('status'))
            except Exception as e:
                logger.warning(f"Error setting superapp_status: {str(e)}")
            
            try:
                if 'description' in decrypted_data and decrypted_data.get('description'):
                    payment.description = str(decrypted_data.get('description'))
            except Exception as e:
                logger.warning(f"Error setting description: {str(e)}")
            
            try:
                if 'finishTime' in decrypted_data:
                    finish_time_val = safe_int(decrypted_data.get('finishTime'))
                    if finish_time_val is not None:
                        payment.finish_time = finish_time_val
            except Exception as e:
                logger.warning(f"Error setting finish_time: {str(e)}")
            
            try:
                if 'orderAmount' in decrypted_data:
                    order_amount_val = safe_int(decrypted_data.get('orderAmount'))
                    if order_amount_val is not None:
                        payment.order_amount = order_amount_val
            except Exception as e:
                logger.warning(f"Error setting order_amount: {str(e)}")
            
            try:
                if 'paidAmount' in decrypted_data:
                    paid_amount_val = safe_int(decrypted_data.get('paidAmount'))
                    if paid_amount_val is not None:
                        payment.paid_amount = paid_amount_val
            except Exception as e:
                logger.warning(f"Error setting paid_amount: {str(e)}")
            
            try:
                if 'paymentProduct' in decrypted_data and decrypted_data.get('paymentProduct'):
                    payment.payment_product = str(decrypted_data.get('paymentProduct'))
            except Exception as e:
                logger.warning(f"Error setting payment_product: {str(e)}")
            
            try:
                if 'callbackInfo' in decrypted_data and decrypted_data.get('callbackInfo'):
                    callback_info = str(decrypted_data.get('callbackInfo'))
                    payment.callback_info = callback_info
                    payment.order_id = callback_info  # Also store in order_id for compatibility
            except Exception as e:
                logger.warning(f"Error setting callback_info: {str(e)}")
            
            # Store original payment fields (for refunds) with safe handling
            try:
                if 'originalOutBizId' in decrypted_data and decrypted_data.get('originalOutBizId'):
                    payment.original_out_biz_id = str(decrypted_data.get('originalOutBizId'))
            except Exception as e:
                logger.warning(f"Error setting original_out_biz_id: {str(e)}")
            
            try:
                if 'originalPrepayId' in decrypted_data and decrypted_data.get('originalPrepayId'):
                    payment.original_prepay_id = str(decrypted_data.get('originalPrepayId'))
            except Exception as e:
                logger.warning(f"Error setting original_prepay_id: {str(e)}")
            
            try:
                if 'originalPaymentOrderId' in decrypted_data and decrypted_data.get('originalPaymentOrderId'):
                    payment.original_payment_order_id = str(decrypted_data.get('originalPaymentOrderId'))
            except Exception as e:
                logger.warning(f"Error setting original_payment_order_id: {str(e)}")
            
            try:
                if 'originalOrderAmount' in decrypted_data:
                    original_order_amount_val = safe_int(decrypted_data.get('originalOrderAmount'))
                    if original_order_amount_val is not None:
                        payment.original_order_amount = original_order_amount_val
            except Exception as e:
                logger.warning(f"Error setting original_order_amount: {str(e)}")
            
            try:
                if 'originalPaidAmount' in decrypted_data:
                    original_paid_amount_val = safe_int(decrypted_data.get('originalPaidAmount'))
                    if original_paid_amount_val is not None:
                        payment.original_paid_amount = original_paid_amount_val
            except Exception as e:
                logger.warning(f"Error setting original_paid_amount: {str(e)}")
        
        # Update amount if provided (convert from cents to decimal)
        if order_amount or paid_amount:
            try:
                amount = safe_amount_from_cents(order_amount or paid_amount)
                if amount > 0:
                    payment.amount = amount
            except Exception as e:
                logger.warning(f"Error updating amount: {str(e)}")
        
        # Update currency if provided
        if currency_code:
            try:
                payment.currency = str(currency_code)[:3]  # Ensure max 3 chars
            except Exception as e:
                logger.warning(f"Error updating currency: {str(e)}")
        
        # Update status based on trade_status
        if trade_status:
            try:
                if trade_status == 'SUCCESS':
                    payment.status = 'completed'
                elif trade_status in ['FAILED', 'FAIL']:
                    payment.status = 'failed'
                elif trade_status in ['PENDING', 'PROCESSING']:
                    payment.status = 'processing'
            except Exception as e:
                logger.warning(f"Error updating status: {str(e)}")
        
        payment.save()
        logger.info(f"Updated payment {payment_ref} with status: {payment.status}")
    
    except Exception as e:
        # Log database error with full context to db_errors logger
        error_details = {
            "error": str(e),
            "error_type": type(e).__name__,
            "traceback": traceback.format_exc(),
            "payment_ref": payment_ref,
            "prepay_id": prepay_id,
            "decrypted_data": decrypted_data if 'decrypted_data' in locals() else None,
            "ciphertext_preview": ciphertext[:100] + "..." if ciphertext and len(ciphertext) > 100 else ciphertext,
            "timestamp": timezone.now().isoformat(),
        }
        db_error_logger.error(f"Database error processing payment: {json.dumps(error_details, indent=2, default=str)}")
        
        # Also log to regular logger for console visibility
        logger.error(f"Database error processing payment data: {str(e)}\n{traceback.format_exc()}")
    
    # Always return success response regardless of database errors
    # This ensures SuperApp doesn't retry the callback unnecessarily
    # Payment data is saved in callback-payload folder for manual review
    return Response({"code": "SUCCESS"}, status=status.HTTP_200_OK)


class PaymentStatsView(APIView):
    """
    Get payment statistics
    GET /api/payments/stats/ - Get overall payment statistics
    GET /api/payments/stats/?h5_app_id={id} - Get stats for specific H5 app
    """
    permission_classes = [AllowAny]  # Adjust permissions as needed
    
    def get(self, request):
        h5_app_id = request.query_params.get('h5_app_id')
        
        # Base queryset
        if h5_app_id:
            queryset = Payment.objects.filter(h5_app_id=h5_app_id)
        else:
            queryset = Payment.objects.all()
        
        # Calculate statistics
        stats = {
            'total_payments': queryset.count(),
            'completed_payments': queryset.filter(status='completed').count(),
            'pending_payments': queryset.filter(status='pending').count(),
            'failed_payments': queryset.filter(status='failed').count(),
            'total_amount': queryset.aggregate(total=Sum('amount'))['total'] or 0,
            'completed_amount': queryset.filter(status='completed').aggregate(
                total=Sum('amount')
            )['total'] or 0,
        }
        
        serializer = PaymentStatsSerializer(stats)
        return Response(serializer.data)


class PaymentCallbackLogsView(generics.ListAPIView):
    """
    Get payment callback logs for debugging
    GET /api/payments/callback-logs/ - List all callback logs
    GET /api/payments/callback-logs/?payment_id={id} - Filter by payment
    """
    serializer_class = PaymentCallbackLogSerializer
    permission_classes = [AllowAny]  # Adjust permissions as needed
    
    def get_queryset(self):
        queryset = PaymentCallbackLog.objects.select_related('payment').all()
        
        # Filter by payment ID
        payment_id = self.request.query_params.get('payment_id')
        if payment_id:
            queryset = queryset.filter(payment_id=payment_id)
        
        # Filter by success status
        is_successful = self.request.query_params.get('is_successful')
        if is_successful is not None:
            queryset = queryset.filter(is_successful=is_successful.lower() == 'true')
        
        return queryset.order_by('-received_at')
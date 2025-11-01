"""
Helper functions for payment callback processing
These functions help break down the large payment_callback view into manageable pieces
"""
import json
import re
import logging
import traceback
from pathlib import Path
from datetime import datetime
from django.utils import timezone
from django.conf import settings

from .models import H5App
from .services import DecryptionService
from .decryption_service_docs import DocumentationDecryptionService
from .decryption_service_java import JavaDecryptionService

logger = logging.getLogger('payments')


def extract_raw_body(request):
    """Extract raw request body from DRF request."""
    raw_body = None
    try:
        django_request = request._request if hasattr(request, '_request') else request
        if hasattr(django_request, 'body'):
            body_bytes = django_request.body
            if hasattr(body_bytes, 'read'):
                body_bytes = body_bytes.read()
            if isinstance(body_bytes, bytes):
                raw_body = body_bytes.decode('utf-8')
            else:
                raw_body = body_bytes
            logger.info(f"Raw body captured: {len(raw_body)} characters")
    except Exception as e:
        logger.warning(f"Could not capture raw body: {str(e)}")
        logger.warning(traceback.format_exc())
    return raw_body


def extract_ciphertext_from_raw_body(raw_body):
    """Extract ciphertext directly from raw body string without JSON parsing."""
    if not raw_body:
        return None
    
    ciphertext_pattern = r'"ciphertext"\s*:\s*"'
    match_start = re.search(ciphertext_pattern, raw_body)
    
    if not match_start:
        return None
    
    start_pos = match_start.end()
    pos = start_pos
    ciphertext_value = []
    
    while pos < len(raw_body):
        char = raw_body[pos]
        if char == '\\':
            if pos + 1 < len(raw_body):
                ciphertext_value.append(char + raw_body[pos + 1])
                pos += 2
                continue
        elif char == '"':
            break
        else:
            ciphertext_value.append(char)
        pos += 1
    
    if pos < len(raw_body):
        ciphertext_escaped = ''.join(ciphertext_value)
        try:
            ciphertext_full = bytes(ciphertext_escaped, 'utf-8').decode('unicode_escape')
        except:
            ciphertext_full = ciphertext_escaped
        logger.info(f"Ciphertext extracted from raw body: {len(ciphertext_full)} characters")
        return ciphertext_full
    
    return None


def extract_request_headers(request):
    """Extract headers from DRF request."""
    headers = {}
    django_request = request._request if hasattr(request, '_request') else request
    
    if hasattr(django_request, 'headers'):
        for key, value in django_request.headers.items():
            headers[key] = value
    
    meta = request.META if hasattr(request, 'META') else (django_request.META if hasattr(django_request, 'META') else {})
    
    for key, value in meta.items():
        if key.startswith('HTTP_'):
            header_name = key[5:].replace('_', '-').title()
            if header_name not in headers:
                headers[header_name] = value
        elif key in ['CONTENT_TYPE', 'CONTENT_LENGTH']:
            header_name = key.replace('_', '-').title()
            if header_name not in headers:
                headers[header_name] = value
    
    if not headers.get('Content-Type') and meta.get('CONTENT_TYPE'):
        headers['Content-Type'] = meta.get('CONTENT_TYPE')
    
    return headers


def save_callback_payload(payload_data, headers, raw_body):
    """Save callback payload to JSON file."""
    filepath = None
    
    try:
        callback_dir = Path(settings.BASE_DIR) / 'callback-payload'
        callback_dir.mkdir(exist_ok=True)
        
        timestamp = datetime.now().strftime('%H%M%S_%d%m%Y')
        filename = f"callback_{timestamp}.json"
        filepath = callback_dir / filename
        
        saved_data = {
            "timestamp": datetime.now().isoformat(),
            "received_at": timezone.now().isoformat(),
            "headers": headers,
            "payload": payload_data,
            "raw_body": raw_body
        }
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(saved_data, f, indent=2, ensure_ascii=False, separators=(',', ': '))
        
        logger.info(f"Callback payload saved to: {filepath}")
        return filepath, saved_data
    except Exception as e:
        logger.error(f"Error saving callback payload to file: {str(e)}")
        return None, None


def log_ciphertext_to_file(ciphertext, prepay_id, serial_no, algorithm, nonce, associated_data):
    """Log ciphertext to separate folder."""
    if not ciphertext:
        return
    
    try:
        ciphertext_dir = Path(settings.BASE_DIR) / 'ciphertext-logs'
        ciphertext_dir.mkdir(exist_ok=True)
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        identifier = f"{prepay_id or serial_no or 'unknown'}"
        filename = f"ciphertext_{timestamp}_{identifier}.txt"
        ciphertext_filepath = ciphertext_dir / filename
        
        with open(ciphertext_filepath, 'w', encoding='utf-8') as f:
            f.write(f"# Ciphertext Log\n")
            f.write(f"# Timestamp: {datetime.now().isoformat()}\n")
            f.write(f"# Received At: {timezone.now().isoformat()}\n")
            f.write(f"# Serial No: {serial_no or 'N/A'}\n")
            f.write(f"# Prepay ID: {prepay_id or 'N/A'}\n")
            f.write(f"# Algorithm: {algorithm}\n")
            f.write(f"# Nonce: {nonce or 'N/A'}\n")
            f.write(f"# Associated Data: {associated_data or 'N/A'}\n")
            f.write(f"# Ciphertext Length: {len(ciphertext)} characters\n")
            f.write(f"# \n")
            f.write(f"# Ciphertext (Base64 - Raw, Unformatted from Payload):\n")
            f.write(ciphertext)
        
        logger.info(f"Ciphertext saved to: {ciphertext_filepath} ({len(ciphertext)} chars)")
    except Exception as e:
        logger.error(f"Error saving ciphertext to separate folder: {str(e)}")
        logger.error(traceback.format_exc())


def get_or_create_h5_app(serial_no):
    """Get or create H5App for the given serial number."""
    WORKING_ENCRYPTION_KEY = "4tmvsbJaVBQPFxsum+c3lA=="
    
    if serial_no:
        try:
            return H5App.objects.get(app_key=serial_no)
        except H5App.DoesNotExist:
            logger.warning(f"H5App not found for serialNo: {serial_no}, creating default app with working key")
            return H5App.objects.create(
                name=f"Auto-created app for {serial_no}",
                app_key=serial_no,
                encryption_key=WORKING_ENCRYPTION_KEY,
                notify_url="",
                is_active=True
            )
    else:
        try:
            return H5App.objects.get(app_key="__default__")
        except H5App.DoesNotExist:
            return H5App.objects.create(
                name="Default Payment App",
                app_key="__default__",
                encryption_key=WORKING_ENCRYPTION_KEY,
                notify_url="",
                is_active=True
            )


def decrypt_ciphertext_with_fallback(ciphertext, encryption_key, algorithm, nonce, associated_data, filepath, saved_data):
    """Decrypt ciphertext with multiple fallback methods."""
    decrypted_data = None
    
    try:
        decrypted_data = JavaDecryptionService.decrypt_to_dict(
            associated_data=associated_data,
            nonce=nonce,
            ciphertext=ciphertext,
            encryption_key=encryption_key
        )
        logger.info(f"Successfully decrypted data using Java pattern method")
        
        if filepath and saved_data:
            try:
                saved_data['decrypted_data'] = decrypted_data
                with open(filepath, 'w', encoding='utf-8') as f:
                    json.dump(saved_data, f, indent=2, ensure_ascii=False)
            except Exception as e:
                logger.warning(f"Could not update callback file with decrypted data: {str(e)}")
    except ImportError as e:
        logger.warning(f"PyCryptodome not available ({str(e)}), falling back to old decryption method")
        try:
            decrypted_data = DecryptionService.decrypt_ciphertext(
                ciphertext=ciphertext,
                encryption_key=encryption_key,
                algorithm=algorithm,
                nonce=nonce,
                associated_data=associated_data
            )
            logger.info(f"Successfully decrypted data using fallback method")
        except Exception as fallback_error:
            logger.warning(f"Fallback decryption also failed: {str(fallback_error)}")
    except ValueError as e:
        logger.warning(f"Java decryption method failed ({str(e)}), trying Python documentation method")
        try:
            decrypted_data = DocumentationDecryptionService.decrypt_to_dict(
                associated_data=associated_data or "",
                nonce=nonce,
                ciphertext=ciphertext,
                encryption_key=encryption_key
            )
            logger.info(f"Successfully decrypted data using Python documentation method")
        except Exception as fallback2_error:
            logger.warning(f"Python documentation method also failed: {str(fallback2_error)} - trying original method")
            try:
                decrypted_data = DecryptionService.decrypt_ciphertext(
                    ciphertext=ciphertext,
                    encryption_key=encryption_key,
                    algorithm=algorithm,
                    nonce=nonce,
                    associated_data=associated_data
                )
                logger.info(f"Successfully decrypted data using original method")
            except Exception as fallback3_error:
                logger.warning(f"All decryption methods failed: {str(fallback3_error)}")
    except Exception as e:
        logger.warning(f"Failed to decrypt ciphertext: {str(e)}")
    
    return decrypted_data


def process_and_save_payment(h5_app, ciphertext, decrypted_data, prepay_id, serial_no, db_error_logger):
    """Process decrypted data and save/update payment record."""
    from .models import Payment
    
    def safe_int(value, default=None):
        """Safely convert value to int, return default if conversion fails"""
        if value is None:
            return default
        try:
            return int(value)
        except (ValueError, TypeError):
            logger.warning(f"Could not convert {value} to int, using default {default}")
            return default
    
    def safe_amount_from_cents(value, default=0.0):
        """Safely convert cents to decimal amount"""
        if value is None:
            return default
        try:
            return float(value) / 100
        except (ValueError, TypeError):
            logger.warning(f"Could not convert {value} to amount, using default {default}")
            return default
    
    # Extract data from decrypted payload
    if decrypted_data:
        out_biz_id = decrypted_data.get('outBizId')
        decrypted_prepay_id = decrypted_data.get('prepayId')
        trade_status = decrypted_data.get('status')
        order_amount = decrypted_data.get('orderAmount')
        paid_amount = decrypted_data.get('paidAmount')
        currency_code = decrypted_data.get('currency', 'USD')
    else:
        out_biz_id = None
        decrypted_prepay_id = None
        trade_status = None
        order_amount = None
        paid_amount = None
        currency_code = 'USD'
    
    # Determine payment reference
    payment_ref = out_biz_id or prepay_id or decrypted_prepay_id or serial_no or "unknown"
    if not payment_ref or payment_ref == "unknown":
        payment_ref = f"callback_{int(timezone.now().timestamp())}"
        logger.warning(f"No payment reference found, using generated: {payment_ref}")
    
    try:
        # Find or create payment
        try:
            payment = Payment.objects.get(payment_ref=payment_ref, h5_app=h5_app)
        except Payment.DoesNotExist:
            amount = safe_amount_from_cents(order_amount or paid_amount, default=0.0)
            payment = Payment.objects.create(
                h5_app=h5_app,
                payment_ref=payment_ref,
                amount=amount,
                currency=currency_code or 'USD',
                status='pending'
            )
            logger.info(f"Created new payment record: {payment_ref}")
        
        # Update payment fields
        payment.ciphertext = ciphertext
        payment.decrypted_data = decrypted_data
        payment.callback_received_at = timezone.now()
        
        # Update decrypted fields if available
        if decrypted_data:
            _update_payment_fields(payment, decrypted_data, safe_int)
        
        # Update amount, currency, and status
        if order_amount or paid_amount:
            amount = safe_amount_from_cents(order_amount or paid_amount)
            if amount > 0:
                payment.amount = amount
        
        if currency_code:
            payment.currency = str(currency_code)[:3]
        
        if trade_status:
            if trade_status == 'SUCCESS':
                payment.status = 'completed'
            elif trade_status in ['FAILED', 'FAIL']:
                payment.status = 'failed'
            elif trade_status in ['PENDING', 'PROCESSING']:
                payment.status = 'processing'
        
        payment.save()
        logger.info(f"Updated payment {payment_ref} with status: {payment.status}")
        
    except Exception as e:
        error_details = {
            "error": str(e),
            "error_type": type(e).__name__,
            "traceback": traceback.format_exc(),
            "payment_ref": payment_ref,
            "prepay_id": prepay_id,
            "decrypted_data": decrypted_data,
            "ciphertext_preview": ciphertext[:100] + "..." if ciphertext and len(ciphertext) > 100 else ciphertext,
            "timestamp": timezone.now().isoformat(),
        }
        db_error_logger.error(f"Database error processing payment: {json.dumps(error_details, indent=2, default=str)}")
        logger.error(f"Database error processing payment data: {str(e)}\n{traceback.format_exc()}")


def _update_payment_fields(payment, decrypted_data, safe_int):
    """Update payment fields from decrypted data."""
    field_mappings = [
        ('appId', 'app_id'),
        ('mchId', 'mch_id'),
        ('outBizId', 'out_biz_id'),
        ('prepayId', 'prepay_id'),
        ('paymentOrderId', 'payment_order_id'),
        ('tradeType', 'trade_type'),
        ('status', 'superapp_status'),
        ('description', 'description'),
        ('paymentProduct', 'payment_product'),
        ('originalOutBizId', 'original_out_biz_id'),
        ('originalPrepayId', 'original_prepay_id'),
        ('originalPaymentOrderId', 'original_payment_order_id'),
    ]
    
    for json_key, model_field in field_mappings:
        if json_key in decrypted_data and decrypted_data.get(json_key):
            try:
                setattr(payment, model_field, str(decrypted_data.get(json_key)))
            except Exception as e:
                logger.warning(f"Error setting {model_field}: {str(e)}")
    
    # Special handling for integer fields
    int_fields = [
        ('finishTime', 'finish_time'),
        ('orderAmount', 'order_amount'),
        ('paidAmount', 'paid_amount'),
        ('originalOrderAmount', 'original_order_amount'),
        ('originalPaidAmount', 'original_paid_amount'),
    ]
    
    for json_key, model_field in int_fields:
        if json_key in decrypted_data:
            try:
                value = safe_int(decrypted_data.get(json_key))
                if value is not None:
                    setattr(payment, model_field, value)
            except Exception as e:
                logger.warning(f"Error setting {model_field}: {str(e)}")
    
    # Handle callbackInfo
    if 'callbackInfo' in decrypted_data and decrypted_data.get('callbackInfo'):
        try:
            callback_info = str(decrypted_data.get('callbackInfo'))
            payment.callback_info = callback_info
            payment.order_id = callback_info
        except Exception as e:
            logger.warning(f"Error setting callback_info: {str(e)}")


